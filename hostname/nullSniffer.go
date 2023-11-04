package hostname

import (
	"bytes"
	"fmt"
	"net"
)

type nullSniffer struct{}

func (sniffer *nullSniffer) SniffHostName(c *net.TCPConn) (string, error) {
	return "", fmt.Errorf("null sniffer always fails")
}

func (sniffer *nullSniffer) GetBufferedData() *bytes.Buffer {
	return &bytes.Buffer{}
}

var nullSingleton = &Sniffer{&nullSniffer{}}

func NewNullSniffer() *Sniffer {
	return nullSingleton
}
