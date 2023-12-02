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
	snifferInterface
}

type SnifferInterface interface {
	SniffHostName(c net.Conn) (string, error)
	GetBufferedData() io.WriterTo
}

type snifferInterface = SnifferInterface

func NewSnifferFromInterface(snifferInterface SnifferInterface) *Sniffer {
	return &Sniffer{snifferInterface}
}

type SniffStrategy struct {
	sniffStrategyInterface
}

type SniffStrategyInterface interface {
	SniffHostName(r io.Reader) (string, error)
}

type sniffStrategyInterface = SniffStrategyInterface

func NewSniffStrategyFromInterface(strategyInterface SniffStrategyInterface) *SniffStrategy {
	return &SniffStrategy{strategyInterface}
}

type snifferStrategyFunction func(r io.Reader) (string, error)

func (sniffer snifferStrategyFunction) SniffHostName(r io.Reader) (string, error) {
	return sniffer(r)
}
