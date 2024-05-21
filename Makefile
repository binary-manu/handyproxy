.PHONY: all clean test release

LDFLAGS = -linkmode=external -extld=gcc -extldflags=-static

ifneq "$(HANDYPROXY_VERSION)" ""
  LDFLAGS += -X main.version=$(HANDYPROXY_VERSION)
endif

GOFLAGS = -ldflags '$(LDFLAGS)'
TARGET = handyproxy

all: $(TARGET)

release: all
release: LDFLAGS += -s -w

$(TARGET):
	go build $(GOFLAGS) ./cmd/$(TARGET)

clean:
	rm -f $(TARGET)

test:
	go test ./...

# Don't try to remake the Makefile
$(MAKEFILE_LIST):;
