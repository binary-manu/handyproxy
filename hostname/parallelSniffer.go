package hostname

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"
)

type parallelSniffer struct {
	sniffers     []*SniffStrategy
	timeout      time.Duration
	maxData      int64
	bufferedData bytes.Buffer
}

func (sniffer *parallelSniffer) SniffHostName(c *net.TCPConn) (rHostName string, rError error) {
	if sniffer.bufferedData.Len() > 0 {
		panic("parallelSniffer instances cannot be reused")
	}

	var reader io.Reader = c
	readSync := make(chan struct{})
	defer func() {
		<-readSync
		err := c.SetReadDeadline(time.Time{})
		if err != nil {
			rHostName = ""
			rError = fmt.Errorf("failed to disable read deadline on TCP conn: %w", err)
		}
	}()
	// Ensure bytes used for detection are buffered so that they can then be sent
	// to the destination
	reader = io.TeeReader(reader, &sniffer.bufferedData)

	// Each strategy gets its own reader so that they can run in parallel
	readersForStrategies := make([]io.Reader, len(sniffer.sniffers))
	writersForStrategies := make([]io.Writer, len(sniffer.sniffers))
	defer func() {
		for _, r := range readersForStrategies {
			_ = r.(io.Closer).Close()
		}
		for _, w := range writersForStrategies {
			_ = w.(io.Closer).Close()
		}
	}()
	hostNamesFound := make(chan string, len(sniffer.sniffers))
	for i, strategy := range sniffer.sniffers {
		readersForStrategies[i], writersForStrategies[i] = io.Pipe()
		go func(i int, strategy sniffStrategy) {
			name, _ := strategy.SniffHostName(readersForStrategies[i])
			if name != "" {
				hostNamesFound <- name
			}
			// Keep dumping data, otherwise the MultiWriter will stall
			_, _ = io.Copy(io.Discard, readersForStrategies[i])
		}(i, strategy)
	}
	forkData := io.MultiWriter(writersForStrategies...)

	go func() {
		defer close(readSync)
		err := c.SetReadDeadline(time.Now().Add(sniffer.timeout))
		if err != nil {
			return
		}
		_, _ = io.CopyN(forkData, reader, sniffer.maxData)
	}()

	select {
	case hn := <-hostNamesFound:
		// If this fails, the code will simply stall until the reading gorutine
		// ends on its own
		_ = c.SetReadDeadline(time.Now())
		return hn, nil
	case <-readSync:
		return "", fmt.Errorf("all hostname sniffers failed")
	}

}

func (sniffer *parallelSniffer) GetBufferedData() *bytes.Buffer {
	return &sniffer.bufferedData
}

type ParallelSnifferOption func(sniffer *parallelSniffer)

func WithParallelSnifferStrategy(aSniffer *SniffStrategy) ParallelSnifferOption {
	return func(sniffer *parallelSniffer) {
		sniffer.sniffers = append(sniffer.sniffers, aSniffer)
	}
}

func WithParallelMaxData(max int64) ParallelSnifferOption {
	return func(sniffer *parallelSniffer) {
		if max > 0 {
			sniffer.maxData = max
		} else {
			sniffer.maxData = SniffDefaultMaxData
		}
	}
}

func WithParallelTimeout(timeout time.Duration) ParallelSnifferOption {
	return func(sniffer *parallelSniffer) {
		if timeout > 0 {
			sniffer.timeout = timeout
		} else {
			sniffer.timeout = SniffDefaultTimeout
		}
	}
}

func NewParallelSniffer(opts ...ParallelSnifferOption) *Sniffer {
	sniffer := parallelSniffer{
		maxData: SniffDefaultMaxData,
		timeout: SniffDefaultTimeout,
	}
	for _, opts := range opts {
		opts(&sniffer)
	}
	return &Sniffer{&sniffer}
}
