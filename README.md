<p align="center">
  <img src="https://i.ibb.co/0p9d0Lzb/20260604-033822.png" alt="Walloperz" width="100%">
</p>

<div align="center">

# SSH-RECHAT

### *Continued ssh.chat*

[![License](https://img.shields.io/github/license/CCwhiteX/ssh-rechat?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)

*Fork and continuation of the project [ssh.chat](https://github.com/shazow/ssh-chat) by [shazow](https://github.com/shazow).*

A custom SSH server that becomes a chat room. Instead of a shell, you get a chat prompt.  
Connect, chat, and have fun — all over SSH!

</div>

---

## Dependencies

| Dependency | Version      | Description                |
|------------|--------------|----------------------------|
| [Go](https://go.dev/) | 1.25+        | The Go programming language |
| [Make](https://www.gnu.org/software/make/) | Any recent   | Build automation tool      |

---

## Build

```bash
# Clone the repo
git clone https://github.com/your-username/ssh-rechat.git
cd ssh-rechat

# Tidy up Go modules
go mod tidy

# Build everything
make all
```

---

Usage

Run the server

```bash
./ssh-chat
```

Help

```bash
./ssh-chat --help
```

Version

```bash
./ssh-chat --version
```

---

Configuration

Configuration is done through the Makefile. You can set the port and other options there.

Example:

```makefile
PORT ?= 22
```

Override at build time:

```bash
make all PORT=22
```

---

Connect

```bash
ssh localhost -p 22
```

---
License

This project follows the license of the original shazow/ssh-chat

<div align="center">

Made with by CCwhiteX | SergRikhter | Chimera

</div>
