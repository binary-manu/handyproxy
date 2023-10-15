package hostname

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"
)

type HostNameSniffStrategy interface {
	SniffHostName(r io.Reader) (string, error)
}

type snifferFunction func(r io.Reader) (string, error)

func (sniffer snifferFunction) SniffHostName(r io.Reader) (string, error) {
	return sniffer(r)
}

type HostNameSniffer struct {
	sniffers     []HostNameSniffStrategy
	timeout      time.Duration
	maxData      int64
	bufferedData bytes.Buffer
}

func (sniffer *HostNameSniffer) SniffHostName(c *net.TCPConn) (string, error) {
	var reader io.Reader = c
	readSync := make(chan struct{})
	defer func() {
		<-readSync
		c.SetReadDeadline(time.Time{})
	}()
	// Ensure bytes used for detection are buffered so that they can then be sent
	// to the destinaton
	reader = io.TeeReader(reader, &sniffer.bufferedData)

	// Each strategy gets its own reader so that they can run in parallel
	readersForStrategies := make([]io.Reader, len(sniffer.sniffers))
	writersForStrategies := make([]io.Writer, len(sniffer.sniffers))
	hostNamesFound := make(chan string, len(sniffer.sniffers))
	for i, strategy := range sniffer.sniffers {
		readersForStrategies[i], writersForStrategies[i] = io.Pipe()
		defer readersForStrategies[i].(io.Closer).Close()
		defer writersForStrategies[i].(io.Closer).Close()
		go func(i int, strategy HostNameSniffStrategy) {
			name, _ := strategy.SniffHostName(readersForStrategies[i])
			if name != "" {
				hostNamesFound <- name
			}
			io.Copy(io.Discard, readersForStrategies[i])
		}(i, strategy)
	}
	forkData := io.MultiWriter(writersForStrategies...)

	go func() {
		defer close(readSync)
		c.SetReadDeadline(time.Now().Add(sniffer.timeout))
		io.CopyN(forkData, reader, sniffer.maxData)
	}()

	select {
	case hn := <-hostNamesFound:
		c.SetReadDeadline(time.Now())
		return hn, nil
	case <-readSync:
		return "", fmt.Errorf("all hostname sniffers failed")
	}

}

type SnifferOption func(sniffer *HostNameSniffer)

func WithSnifferStrategy(aSniffer HostNameSniffStrategy) SnifferOption {
	return func(sniffer *HostNameSniffer) {
		sniffer.sniffers = append(sniffer.sniffers, aSniffer)
	}
}

func WithMaxData(max int64) SnifferOption {
	return func(sniffer *HostNameSniffer) {
		sniffer.maxData = max
	}
}

func WithTimeout(timeout time.Duration) SnifferOption {
	return func(sniffer *HostNameSniffer) {
		sniffer.timeout = timeout
	}
}

func NewSniffer(opts ...SnifferOption) *HostNameSniffer {
	var sniffer HostNameSniffer
	for _, opts := range opts {
		opts(&sniffer)
	}
	return &sniffer
}

func (sniffer *HostNameSniffer) GetBufferedData() *bytes.Buffer {
	return &sniffer.bufferedData
}
