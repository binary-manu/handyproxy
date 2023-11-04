package hostname

import (
	"io"
	"net"
	"strings"
	"time"
)

const SniffDefaultMaxData = 8192
const SniffDefaultTimeout = time.Second

type FatalError struct {
	wrapped error
}

func (e *FatalError) Error() string {
	var msg strings.Builder
	msg.WriteString("hostname sniffing fatal error")
	if e.wrapped != nil {
		msg.WriteString(": ")
		msg.WriteString(e.wrapped.Error())
	}
	return msg.String()
}

func (e *FatalError) Unwrap() error {
	return e.wrapped
}

func WrapFatal(err error) error {
	return &FatalError{err}
}

type Sniffer struct {
	sniffer
}

type sniffer interface {
	SniffHostName(c *net.TCPConn) (string, error)
	GetBufferedData() io.WriterTo
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
