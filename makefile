APPLICATION=sshoneypot
VERSION ?= dev

OS ?= linux
ARCH ?= amd64

BUILD_DIR=target
DIST_DIR=dist

.PHONY: build package clean

build:
	@mkdir -p $(BUILD_DIR)
	GO111MODULE=on GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=0 \
	go build -a -ldflags="-s -w" -v \
	-o $(BUILD_DIR)/$(APPLICATION) ./cmd/main.go

package: build
	@mkdir -p $(DIST_DIR)
	tar -C $(BUILD_DIR) -czf \
	$(DIST_DIR)/$(APPLICATION)-$(VERSION)-$(OS)-$(ARCH).tar.gz \
	$(APPLICATION)

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)