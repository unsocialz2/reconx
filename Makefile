BINARY     := reconx
VERSION    := v1.0.0
BUILD_DIR  := ./dist
MAIN       := ./cmd/reconx

LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build test clean install lint release help

all: build

## build: Compile for current OS/arch
build:
	@echo "  \033[36m▶\033[0m Building $(BINARY) $(VERSION)..."
	@go build $(LDFLAGS) -o $(BINARY) $(MAIN)
	@echo "  \033[32m✓\033[0m Built → ./$(BINARY)"

## install: Build and install to /usr/local/bin
install: build
	@sudo mv $(BINARY) /usr/local/bin/$(BINARY)
	@echo "  \033[32m✓\033[0m Installed to /usr/local/bin/$(BINARY)"

## test: Run all tests
test:
	@go test ./... -v 2>&1

## lint: Run go vet
lint:
	@go vet ./...
	@echo "  \033[32m✓\033[0m No issues found"

## release: Cross-compile for Linux, macOS, Windows
release:
	@mkdir -p $(BUILD_DIR)
	@echo "  \033[36m▶\033[0m Cross-compiling..."
	GOOS=linux   GOARCH=amd64   go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   $(MAIN)
	GOOS=linux   GOARCH=arm64   go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   $(MAIN)
	GOOS=darwin  GOARCH=amd64   go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  $(MAIN)
	GOOS=darwin  GOARCH=arm64   go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  $(MAIN)
	GOOS=windows GOARCH=amd64   go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(MAIN)
	@echo "  \033[32m✓\033[0m Binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

## clean: Remove build artifacts
clean:
	@rm -f $(BINARY)
	@rm -rf $(BUILD_DIR)
	@echo "  \033[32m✓\033[0m Cleaned"

## tools: Install all external recon tools
tools:
	@bash install.sh

## init: Generate default config file
init:
	@./$(BINARY) -init

## help: Show this help
help:
	@echo ""
	@echo "  \033[1;32mReconX Makefile\033[0m"
	@echo ""
	@grep -E '^##' Makefile | sed 's/## /  /'
	@echo ""
