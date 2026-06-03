BINARY = ssh-rechat
KEY = host_key
PORT = 22

SRCS = %.go
VERSION := $(shell git describe --tags --dirty --always 2> /dev/null || echo "dev")
LDFLAGS = -X main.Version=$(VERSION) -extldflags "-static"

all: $(BINARY)

$(BINARY): **/**/*.go **/*.go *.go
	go build -ldflags "$(LDFLAGS)" ./cmd/ssh-chat

build: $(BINARY)

clean:
	rm $(BINARY)

$(KEY):
	ssh-keygen -f $(KEY) -P ''

run: $(BINARY) $(KEY)
	./$(BINARY) -i $(KEY) --bind ":$(PORT)" -vv

debug: $(BINARY) $(KEY)
	./$(BINARY) --pprof 6060 -i $(KEY) --bind ":$(PORT)" -vv

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 LDFLAGS='$(LDFLAGS)' ./build_release "github.com/shazow/ssh-chat/cmd/ssh-chat" README.md LICENSE
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 LDFLAGS='$(LDFLAGS)' ./build_release "github.com/shazow/ssh-chat/cmd/ssh-chat" README.md LICENSE
