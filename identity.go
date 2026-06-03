package sshchat

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ccwhitex/ssh-rechat/chat"
	"github.com/ccwhitex/ssh-rechat/chat/message"
	"github.com/ccwhitex/ssh-rechat/internal/humantime"
	"github.com/ccwhitex/ssh-rechat/internal/sanitize"
	"github.com/ccwhitex/ssh-rechat/sshd"
)

type Identity struct {
	sshd.Connection
	id      string
	symbol  string // symbol is displayed as a prefix to the name
	created time.Time
}

func NewIdentity(conn sshd.Connection) *Identity {
	return &Identity{
		Connection: conn,
		id:         sanitize.Name(conn.Name()),
		created:    time.Now(),
	}
}

func (i Identity) ID() string {
	return i.id
}

func (i *Identity) SetID(id string) {
	i.id = id
}

func (i *Identity) SetName(name string) {
	i.SetID(name)
}

func (i *Identity) SetSymbol(symbol string) {
	i.symbol = symbol
}

func (i Identity) Name() string {
	if i.symbol != "" {
		return i.symbol + " " + i.id
	}
	return i.id
}

func (i Identity) Whois(room *chat.Room) string {
	fingerprint := "(no public key)"
	if i.PublicKey() != nil {
		fingerprint = sshd.Fingerprint(i.PublicKey())
	}

	awayMsg := ""
	if m, ok := room.MemberByID(i.ID()); ok {
		isAway, awaySince, awayMessage := m.GetAway()
		if isAway {
			awayMsg = fmt.Sprintf("%s > away: (%s ago) %s", message.Newline, humantime.Since(awaySince), awayMessage)
		}
	}
	return "name: " + i.Name() + message.Newline +
		" > fingerprint: " + fingerprint + message.Newline +
		" > client: " + sanitize.Data(string(i.ClientVersion()), 64) + message.Newline +
		" > joined: " + humantime.Since(i.created) + " ago" +
		awayMsg
}

func (i Identity) WhoisAdmin(room *chat.Room) string {
	ip, _, _ := net.SplitHostPort(i.RemoteAddr().String())
	fingerprint := "(no public key)"
	if i.PublicKey() != nil {
		fingerprint = sshd.Fingerprint(i.PublicKey())
	}

	out := strings.Builder{}
	out.WriteString("name: " + i.Name() + message.Newline +
		" > ip: " + ip + message.Newline +
		" > fingerprint: " + fingerprint + message.Newline +
		" > client: " + sanitize.Data(string(i.ClientVersion()), 64) + message.Newline +
		" > joined: " + humantime.Since(i.created) + " ago")

	if member, ok := room.MemberByID(i.ID()); ok {
		if isAway, awaySince, awayMessage := member.GetAway(); isAway {
			fmt.Fprintf(&out, message.Newline+" > away: (%s ago) %s", humantime.Since(awaySince), awayMessage)
		}
		if !member.LastMsg().IsZero() {
			out.WriteString(message.Newline + " > room/messaged: " + humantime.Since(member.LastMsg()) + " ago")
		}
		if room.IsOp(member.User) {
			out.WriteString(message.Newline + " > room/op: true")
		}
	}

	return out.String()
}
