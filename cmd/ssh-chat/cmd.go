package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"golang.org/x/crypto/ssh"

	sshchat "github.com/ccwhitex/ssh-rechat"
	"github.com/ccwhitex/ssh-rechat/chat"
	"github.com/ccwhitex/ssh-rechat/chat/message"
	"github.com/ccwhitex/ssh-rechat/sshd"

	_ "net/http/pprof"
)

var Version string = "dev"

type Options struct {
	Admin      string   `long:"admin" description:"File of public keys who are admins."`
	Bind       string   `long:"bind" description:"Host and port to listen on." default:"0.0.0.0:2022"`
	Identity   []string `short:"i" long:"identity" description:"Private key to identify server with." default:"~/.ssh/id_rsa"`
	Log        string   `long:"log" description:"Write chat log to this file."`
	Motd       string   `long:"motd" description:"Optional Message of the Day file."`
	Pprof      int      `long:"pprof" description:"Enable pprof http server for profiling."`
	Verbose    bool     `short:"v" long:"verbose" description:"Show verbose logging."`
	Version    bool     `long:"version" description:"Print version and exit."`
	Allowlist  string   `long:"allowlist" description:"Optional file of public keys who are allowed to connect."`
	Whitelist  string   `long:"whitelist" description:"Old name for allowlist option"`
	Passphrase string   `long:"unsafe-passphrase" description:"Require an interactive passphrase to connect. Allowlist feature is more secure."`
}

const extraHelp = `...`

func setupLogging(verbose bool) {
	var level slog.Level
	if verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}
	
	opts := &slog.HandlerOptions{
		Level: level,
	}
	
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)
	
	// Настраиваем все подсистемы на тот же вывод
	sshchat.SetLogger(os.Stderr)
	chat.SetLogger(os.Stderr)
	sshd.SetLogger(os.Stderr)
	message.SetLogger(os.Stderr)
}

func fail(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(code)
}

func main() {
	options := Options{}
	parser := flags.NewParser(&options, flags.Default)
	p, err := parser.Parse()
	if err != nil {
		if p == nil {
			fmt.Print(err)
		}
		if flagErr, ok := err.(*flags.Error); ok && flagErr.Type == flags.ErrHelp {
			fmt.Print(extraHelp)
		}
		return
	}

	if options.Pprof != 0 {
		go func() {
			slog.Info("pprof server started", "port", options.Pprof)
			fmt.Println(http.ListenAndServe(fmt.Sprintf("localhost:%d", options.Pprof), nil))
		}()
	}

	if options.Version {
		fmt.Println(Version)
		return
	}

	// Настройка логирования
	setupLogging(options.Verbose)
	slog.Info("ssh-chat starting", "version", Version)

	auth := sshchat.NewAuth()
	config := sshd.MakeAuth(auth)
	config.ServerVersion = "SSH-2.0-Go ssh-chat"

	for _, privateKeyPath := range options.Identity {
		if strings.HasPrefix(privateKeyPath, "~/") {
			user, err := user.Current()
			if err == nil {
				privateKeyPath = strings.Replace(privateKeyPath, "~", user.HomeDir, 1)
			}
		}

		signer, err := ReadPrivateKey(privateKeyPath)
		if err != nil {
			fail(3, "Failed to read identity private key: %v\n", err)
		}

		config.AddHostKey(signer)
		slog.Info("Added server identity", "fingerprint", sshd.Fingerprint(signer.PublicKey()))
	}

	s, err := sshd.ListenSSH(options.Bind, config)
	if err != nil {
		fail(4, "Failed to listen on socket: %v\n", err)
	}
	defer s.Close()
	s.RateLimit = sshd.NewInputLimiter

	slog.Info("Listening for connections", "address", s.Addr().String())

	host := sshchat.NewHost(s, auth)
	host.SetTheme(message.Themes[0])
	host.Version = Version

	if options.Passphrase != "" {
		auth.SetPassphrase(options.Passphrase)
		slog.Warn("Passphrase authentication enabled (less secure than allowlist)")
	}

	err = auth.LoadOps(loaderFromFile(options.Admin))
	if err != nil {
		fail(5, "Failed to load admins: %v\n", err)
	}

	if options.Allowlist == "" && options.Whitelist != "" {
		slog.Info("--whitelist was renamed to --allowlist, using --whitelist value")
		options.Allowlist = options.Whitelist
	}
	err = auth.LoadAllowlist(loaderFromFile(options.Allowlist))
	if err != nil {
		fail(6, "Failed to load allowlist: %v\n", err)
	}
	auth.SetAllowlistMode(options.Allowlist != "")
	if options.Allowlist != "" {
		slog.Info("Allowlist mode enabled", "file", options.Allowlist)
	}

	if options.Motd != "" {
		host.GetMOTD = func() (string, error) {
			motd, err := os.ReadFile(options.Motd)
			if err != nil {
				return "", err
			}
			motdString := string(motd)
			motdString = strings.Replace(motdString, "\r\n", "\n", -1)
			motdString = strings.Replace(motdString, "\n", "\r\n", -1)
			return motdString, nil
		}
		if motdString, err := host.GetMOTD(); err != nil {
			fail(7, "Failed to load MOTD file: %v\n", err)
		} else {
			host.SetMotd(motdString)
			slog.Info("MOTD loaded", "file", options.Motd)
		}
	}

	if options.Log == "-" {
		host.SetLogging(os.Stdout)
		slog.Info("Chat logging to stdout")
	} else if options.Log != "" {
		fp, err := os.OpenFile(options.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fail(8, "Failed to open log file for writing: %v", err)
		}
		host.SetLogging(fp)
		slog.Info("Chat logging to file", "file", options.Log)
	}

	go host.Serve()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	<-sig
	slog.Info("Interrupt signal detected, shutting down...")
}

func loaderFromFile(path string) sshchat.KeyLoader {
	if path == "" {
		return nil
	}
	return func() ([]ssh.PublicKey, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		var keys []ssh.PublicKey
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				if err.Error() == "ssh: no key found" {
					continue
				}
				return nil, err
			}
			keys = append(keys, key)
		}
		if keys == nil {
			slog.Warn("File contained no keys", "file", path)
		}
		return keys, nil
	}
}