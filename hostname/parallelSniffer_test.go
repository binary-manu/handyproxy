package hostname

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/akutz/memconn"
	"github.com/stretchr/testify/require"
)

func streamRequestViaConn(producer io.Reader, consumer func(net.Conn)) {
	pr, pw := memconn.Pipe()
	defer pr.Close()
	defer pw.Close()
	errCh := make(chan error, 1)
	go func() {
		_, err := io.Copy(pw, producer)
		if err != nil {
			errCh <- err
		}
	}()
	consumer(pr)
	select {
	case err := <-errCh:
		panic(err)
	default:
	}
}

func tableTestHelper[TD testDataInterface](t *testing.T, snifferFactory func() *Sniffer, testData []TD) {
	for _, scenario := range testData {
		t.Run(scenario.GetDescription(), func(t *testing.T) {
			sniffer := snifferFactory()
			reqReader := scenario.ReaderForRequest()
			var hostname string
			var err error
			streamRequestViaConn(reqReader, func(c net.Conn) {
				hostname, err = sniffer.SniffHostName(c)
			})
			scenario.ErrorCheck(t, err)
			scenario.HostnameCheck(t, hostname)
			// Ensure that the unread reueast bytes, plus the buffered portion returned by
			// the sniffer match the original request
			var reqBytes bytes.Buffer
			must(io.Copy(&reqBytes, scenario.ReaderForRequest()))
			var reconstructedReq bytes.Buffer
			must(sniffer.GetBufferedData().WriteTo(&reconstructedReq))
			must(io.Copy(&reconstructedReq, reqReader))
			require.Equal(t, reqBytes.Bytes(), reconstructedReq.Bytes())
		})
	}
}

func TestParallelSnifferWithAFailingStub(t *testing.T) {
	sniffStrategyStubFail := func(c io.Reader) (string, error) {
		return "", fmt.Errorf("stub strategy always fails")
	}

	stub := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStubFail))
	sniffer := NewParallelSniffer(WithParallelSnifferStrategy(stub))
	var hostname string
	var err error
	streamRequestViaConn(&bytes.Buffer{}, func(c net.Conn) {
		hostname, err = sniffer.SniffHostName(c)
	})
	require.Empty(t, hostname)
	require.Error(t, err)
}

func TestParallelSnifferWithASuccessfulStub(t *testing.T) {
	expectedHost := "www.example.com"
	sniffStrategyStubOK := func(c io.Reader) (string, error) {
		return expectedHost, nil
	}

	stub := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStubOK))
	sniffer := NewParallelSniffer(WithParallelSnifferStrategy(stub))
	var hostname string
	var err error
	streamRequestViaConn(&bytes.Buffer{}, func(c net.Conn) {
		hostname, err = sniffer.SniffHostName(c)
	})
	require.Equal(t, expectedHost, hostname)
	require.NoError(t, err)
}

func TestParallelSnifferWithDeadlineExceeded(t *testing.T) {
	sniffStrategyStub := func(c io.Reader) (string, error) {
		// We should not get past this copy unless the connection
		// is closed
		io.CopyN(io.Discard, c, 1)
		return "www.example.com", nil
	}

	stub := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStub))
	sniffer := NewParallelSniffer(WithParallelSnifferStrategy(stub))
	var hostname string
	var err error
	streamRequestViaConn(&bytes.Buffer{}, func(c net.Conn) {
		hostname, err = sniffer.SniffHostName(c)
	})
	require.Empty(t, hostname)
	require.ErrorIs(t, errTimeoutOrDataLimitExceeded, err)
}

func TestParallelSnifferWithHTTPStrategyOnly(t *testing.T) {
	factory := func() *Sniffer {
		return NewParallelSniffer(WithParallelSnifferStrategy(NewHTTPSnifferStrategy()))
	}
	tableTestHelper(t, factory, httpTestTable)
}

func TestParallelSnifferWithTLSStrategyOnly(t *testing.T) {
	factory := func() *Sniffer {
		return NewParallelSniffer(WithParallelSnifferStrategy(NewTLSSnifferStrategy()))
	}
	tableTestHelper(t, factory, tlsTestTable)
}

func TestParallelSnifferWithTLSAndHTTPStrategies(t *testing.T) {
	factory := func() *Sniffer {
		return NewParallelSniffer(
			WithParallelSnifferStrategy(NewTLSSnifferStrategy()),
			WithParallelSnifferStrategy(NewHTTPSnifferStrategy()),
		)
	}
	tableTestHelper(t, factory, httpTestTable)
	tableTestHelper(t, factory, tlsTestTable)
}
