package sshd

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/ccwhitex/ssh-rechat/internal/sanitize"
	"golang.org/x/crypto/ssh"
)

type Auth interface {
	AllowAnonymous() bool
	AcceptPassphrase() bool
	CheckBans(net.Addr, ssh.PublicKey, string) error
	CheckPublicKey(ssh.PublicKey) error
	CheckPassphrase(string) error
	BanAddr(net.Addr, time.Duration)
}

func MakeAuth(auth Auth) *ssh.ServerConfig {
	config := ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			err := auth.CheckBans(conn.RemoteAddr(), key, sanitize.Data(string(conn.ClientVersion()), 64))
			if err != nil {
				return nil, err
			}
			err = auth.CheckPublicKey(key)
			if err != nil {
				return nil, err
			}
			perm := &ssh.Permissions{Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			}}
			return perm, nil
		},

		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			err := auth.CheckBans(conn.RemoteAddr(), nil, sanitize.Data(string(conn.ClientVersion()), 64))
			if err != nil {
				return nil, err
			}
			if auth.AcceptPassphrase() {
				var answers []string
				answers, err = challenge("", "", []string{"Passphrase required to connect: "}, []bool{true})
				if err == nil {
					if len(answers) != 1 {
						err = errors.New("didn't get passphrase")
					} else {
						err = auth.CheckPassphrase(answers[0])
						if err != nil {
							auth.BanAddr(conn.RemoteAddr(), time.Second*2)
						}
					}
				}
			} else if !auth.AllowAnonymous() {
				err = errors.New("public key authentication required")
			}
			return nil, err
		},
	}

	return &config
}

func MakeNoAuth() *ssh.ServerConfig {
	config := ssh.ServerConfig{
		NoClientAuth: false,
		// Auth-related things should be constant-time to avoid timing attacks.
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			perm := &ssh.Permissions{Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			}}
			return perm, nil
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	return &config
}

func Fingerprint(k ssh.PublicKey) string {
	hash := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
