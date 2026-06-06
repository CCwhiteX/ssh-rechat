package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func ReadPrivateKey(path string) (ssh.Signer, error) {
	privateKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %v", err)
	}

	pk, err := ssh.ParsePrivateKey(privateKey)
	if err == nil {
	} else if _, ok := err.(*ssh.PassphraseMissingError); ok {
		passphrase := []byte(os.Getenv("IDENTITY_PASSPHRASE"))
		if len(passphrase) == 0 {
			fmt.Println("Enter passphrase to unlock identity private key:", path)
			passphrase, err = term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("couldn't read passphrase: %v", err)
			}
		}
		return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}

	return pk, err
}
