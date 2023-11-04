//go:build debug

package main

import (
	"flag"
	"net"
)

var defaultOrigin = flag.String("default-origin", "127.0.0.1:5555", "[debug] assume all traffic is targeting this address")

func getOriginalDestination(*net.TCPConn) (origin string, err error) {
	return *defaultOrigin, nil
}
