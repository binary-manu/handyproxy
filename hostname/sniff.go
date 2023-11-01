package hostname

import (
	"bytes"
	"io"
	"net"
	"time"
)

const SniffDefaultMaxData = 8192
const SniffDefaultTimeout = time.Second

type Sniffer struct {
	sniffer
}

type sniffer interface {
	SniffHostName(c *net.TCPConn) (string, error)
	GetBufferedData() *bytes.Buffer
}

type SniffStrategy struct {
	sniffStrategy
}

type sniffStrategy interface {
	SniffHostName(r io.Reader) (string, error)
}

type snifferStrategyFunction func(r io.Reader) (string, error)

func (sniffer snifferStrategyFunction) SniffHostName(r io.Reader) (string, error) {
	return sniffer(r)
}
