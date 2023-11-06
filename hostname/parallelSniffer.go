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

	nSniffers := len(sniffer.sniffers)

	var reader io.Reader = c
	readSync := make(chan struct{})
	defer func() {
		<-readSync
		err := c.SetReadDeadline(time.Time{})
		if err != nil {
			rHostName = ""
			rError = WrapFatal(fmt.Errorf("failed to disable read deadline on TCP conn: %w", err))
		}
	}()
	// Ensure bytes used for detection are buffered so that they can then be sent
	// to the destination
	reader = io.TeeReader(reader, &sniffer.bufferedData)

	// Each strategy gets its own reader so that they can run in parallel
	readersForStrategies := make([]io.Reader, nSniffers)
	writersForStrategies := make([]io.Writer, nSniffers)
	defer func() {
		for _, r := range readersForStrategies {
			if r != nil {
				_ = r.(io.Closer).Close()
			}
		}
		for _, w := range writersForStrategies {
			if w != nil {
				_ = w.(io.Closer).Close()
			}
		}
	}()
	hostNamesFound := make(chan string, nSniffers)
	for i, strategy := range sniffer.sniffers {
		readersForStrategies[i], writersForStrategies[i] = io.Pipe()
		go func(i int, strategy *SniffStrategy) {
			name, _ := strategy.SniffHostName(readersForStrategies[i])
			hostNamesFound <- name
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

	for {
		select {
		case hn := <-hostNamesFound:
			if hn != "" {
				// If this fails, the code will simply stall until the reading goroutine
				// ends on its own
				_ = c.SetReadDeadline(time.Now())
				return hn, nil
			}
			nSniffers--
			if nSniffers <= 0 {
				// Same as above
				_ = c.SetReadDeadline(time.Now())
				return "", fmt.Errorf("all hostname sniffers failed")
			}
		case <-readSync:
			return "", fmt.Errorf("sniff deadline expired or data limit reached")
		}
	}

}

func (sniffer *parallelSniffer) GetBufferedData() io.WriterTo {
	return &sniffer.bufferedData
}

type ParallelSnifferOption func(sniffer *parallelSniffer)

func WithParallelSnifferStrategy(aSniffer *SniffStrategy) ParallelSnifferOption {
	if aSniffer == nil {
		panic("cannot add nil SniffStrategy to parallelSniffer")
	}
	return func(sniffer *parallelSniffer) {
		sniffer.sniffers = append(sniffer.sniffers, aSniffer)
	}
}

func WithParallelMaxData(max int64) ParallelSnifferOption {
	return func(sniffer *parallelSniffer) {
		if max > 0 {
			sniffer.maxData = max
		}
	}
}

func WithParallelTimeout(timeout time.Duration) ParallelSnifferOption {
	return func(sniffer *parallelSniffer) {
		if timeout > 0 {
			sniffer.timeout = timeout
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
	if len(sniffer.sniffers) <= 0 {
		panic("parallelSniffer not configured with any SniffStrategy")
	}

	return NewSnifferFromInterface(&sniffer)
}
