package sshchat

import (
	"io"
	"log/slog"
)

var logger *slog.Logger

func SetLogger(w io.Writer) {
	logger = slog.New(slog.NewTextHandler(w, nil))
}

func init() {
	SetLogger(io.Discard)
}
