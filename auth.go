package sshchat

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ccwhitex/ssh-rechat/set"
	"github.com/ccwhitex/ssh-rechat/sshd"
	"golang.org/x/crypto/ssh"
)

type KeyLoader func() ([]ssh.PublicKey, error)

var ErrNotAllowed = errors.New("not allowed")
var ErrBanned = errors.New("banned")
var ErrIncorrectPassphrase = errors.New("incorrect passphrase")

func newAuthKey(key ssh.PublicKey) string {
	if key == nil {
		return ""
	}
	return sshd.Fingerprint(key)
}

func newAuthItem(key ssh.PublicKey) set.Item {
	return set.StringItem(newAuthKey(key))
}

func newAuthAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, _ := net.SplitHostPort(addr.String())
	return host
}

type Auth struct {
	passphraseHash []byte
	bannedAddr     *set.Set
	bannedClient   *set.Set
	banned         *set.Set
	allowlist      *set.Set
	ops            *set.Set

	settingsMu      sync.RWMutex
	allowlistMode   bool
	opLoader        KeyLoader
	allowlistLoader KeyLoader
}

func NewAuth() *Auth {
	return &Auth{
		bannedAddr:   set.New(),
		bannedClient: set.New(),
		banned:       set.New(),
		allowlist:    set.New(),
		ops:          set.New(),
	}
}

func (a *Auth) AllowlistMode() bool {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return a.allowlistMode
}

func (a *Auth) SetAllowlistMode(value bool) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.allowlistMode = value
}

func (a *Auth) SetPassphrase(passphrase string) {
	if passphrase == "" {
		a.passphraseHash = nil
	} else {
		hashArray := sha256.Sum256([]byte(passphrase))
		a.passphraseHash = hashArray[:]
	}
}

func (a *Auth) AllowAnonymous() bool {
	return !a.AllowlistMode() && a.passphraseHash == nil
}

func (a *Auth) AcceptPassphrase() bool {
	return a.passphraseHash != nil
}

func (a *Auth) CheckBans(addr net.Addr, key ssh.PublicKey, clientVersion string) error {
	authkey := newAuthKey(key)

	var banned bool
	if authkey != "" {
		banned = a.banned.In(authkey)
	}
	if !banned {
		banned = a.bannedAddr.In(newAuthAddr(addr))
	}
	if !banned {
		banned = a.bannedClient.In(clientVersion)
	}
	if banned && !a.IsOp(key) {
		return ErrBanned
	}

	return nil
}

func (a *Auth) CheckPublicKey(key ssh.PublicKey) error {
	authkey := newAuthKey(key)
	allowlisted := a.allowlist.In(authkey)
	if a.AllowAnonymous() || allowlisted || a.IsOp(key) {
		return nil
	} else {
		return ErrNotAllowed
	}
}

func (a *Auth) CheckPassphrase(passphrase string) error {
	if !a.AcceptPassphrase() {
		return errors.New("passphrases not accepted")
	}
	passedPassphraseHash := sha256.Sum256([]byte(passphrase))
	if subtle.ConstantTimeCompare(passedPassphraseHash[:], a.passphraseHash) == 0 {
		return ErrIncorrectPassphrase
	}
	return nil
}

func (a *Auth) Op(key ssh.PublicKey, d time.Duration) {
	if key == nil {
		return
	}
	authItem := newAuthItem(key)
	if d != 0 {
		a.ops.Set(set.Expire(authItem, d))
	} else {
		a.ops.Set(authItem)
	}
	logger.Debug("Added to ops: %q (for %s)", authItem.Key(), d)
}

func (a *Auth) IsOp(key ssh.PublicKey) bool {
	authkey := newAuthKey(key)
	return a.ops.In(authkey)
}

func (a *Auth) LoadOps(loader KeyLoader) error {
	a.settingsMu.Lock()
	a.opLoader = loader
	a.settingsMu.Unlock()
	return a.ReloadOps()
}

func (a *Auth) ReloadOps() error {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return addFromLoader(a.opLoader, a.Op)
}

func (a *Auth) Allowlist(key ssh.PublicKey, d time.Duration) {
	if key == nil {
		return
	}
	var err error
	authItem := newAuthItem(key)
	if d != 0 {
		err = a.allowlist.Set(set.Expire(authItem, d))
	} else {
		err = a.allowlist.Set(authItem)
	}
	if err == nil {
		logger.Debug("Added to allowlist: %q (for %s)", authItem.Key(), d)
	} else {
		logger.Error("Error adding %q to allowlist for %s: %s", authItem.Key(), d, err)
	}
}

func (a *Auth) LoadAllowlist(loader KeyLoader) error {
	a.settingsMu.Lock()
	a.allowlistLoader = loader
	a.settingsMu.Unlock()
	return a.ReloadAllowlist()
}

func (a *Auth) ReloadAllowlist() error {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return addFromLoader(a.allowlistLoader, a.Allowlist)
}

func addFromLoader(loader KeyLoader, adder func(ssh.PublicKey, time.Duration)) error {
	if loader == nil {
		return nil
	}
	keys, err := loader()
	if err != nil {
		logger.Error("Failed to load keys", "error", err)
	}
	for _, key := range keys {
		adder(key, 0)
	}
	return err
}

func (a *Auth) Ban(key ssh.PublicKey, d time.Duration) {
	if key == nil {
		return
	}
	a.BanFingerprint(newAuthKey(key), d)
}

func (a *Auth) BanFingerprint(authkey string, d time.Duration) {
	authItem := set.StringItem(authkey)
	if d != 0 {
		a.banned.Set(set.Expire(authItem, d))
	} else {
		a.banned.Set(authItem)
	}
	logger.Debug("Added to banned: %q (for %s)", authItem.Key(), d)
}

func (a *Auth) BanClient(client string, d time.Duration) {
	item := set.StringItem(client)
	if d != 0 {
		a.bannedClient.Set(set.Expire(item, d))
	} else {
		a.bannedClient.Set(item)
	}
	logger.Debug("Added to banned: %q (for %s)", item.Key(), d)
}

func (a *Auth) Banned() (ip []string, fingerprint []string, client []string) {
	a.banned.Each(func(key string, _ set.Item) error {
		fingerprint = append(fingerprint, key)
		return nil
	})
	a.bannedAddr.Each(func(key string, _ set.Item) error {
		ip = append(ip, key)
		return nil
	})
	a.bannedClient.Each(func(key string, _ set.Item) error {
		client = append(client, key)
		return nil
	})
	return
}

func (a *Auth) BanAddr(addr net.Addr, d time.Duration) {
	authItem := set.StringItem(newAuthAddr(addr))
	if d != 0 {
		a.bannedAddr.Set(set.Expire(authItem, d))
	} else {
		a.bannedAddr.Set(authItem)
	}
	logger.Debug("Added to bannedAddr: %q (for %s)", authItem.Key(), d)
}

func (a *Auth) BanQuery(q string) error {
	r := csv.NewReader(strings.NewReader(q))
	r.Comma = ' '
	fields, err := r.Read()
	if err != nil {
		return err
	}

	var d time.Duration
	if last := fields[len(fields)-1]; !strings.Contains(last, "=") {
		d, err = time.ParseDuration(last)
		if err != nil {
			return err
		}
		fields = fields[:len(fields)-1]
	}
	for _, field := range fields {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid query: %q", q)
		}
		key, value := parts[0], parts[1]
		switch key {
		case "client":
			a.BanClient(value, d)
		case "fingerprint":
			a.BanFingerprint(value, d)
		case "ip":
			ip := net.ParseIP(value)
			if ip.String() == "" {
				return fmt.Errorf("invalid ip value: %q", ip)
			}
			a.BanAddr(&net.TCPAddr{IP: ip}, d)
		default:
			return fmt.Errorf("unknown query field: %q", field)
		}
	}
	return nil
}
