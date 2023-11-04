package hostname

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

type nullSniffer struct{}

func (sniffer *nullSniffer) SniffHostName(*net.TCPConn) (string, error) {
	return "", fmt.Errorf("null sniffer always fails")
}

func (sniffer *nullSniffer) GetBufferedData() io.WriterTo {
	return &bytes.Buffer{}
}

var nullSingleton = &Sniffer{&nullSniffer{}}

func NewNullSniffer() *Sniffer {
	return nullSingleton
}
