all: deps check build
format:
	find . -iname "*.go" -exec gofmt -s -l -w {} \;
check:
	go vet ./...
run:
	go run cmd/HellPot/HellPot.go
deps:
	go mod tidy -v
build:
	go build -ldflags="-s -w -X main.version=$(shell git describe --tags --abbrev=0)" -o HellPot cmd/HellPot/HellPot.go


