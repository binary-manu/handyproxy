package hostname

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/akutz/memconn"
	"github.com/stretchr/testify/require"
)

// Given a reader, make its contents available as a net.Conn using an in-memory
// implementation. The copy from the reader to the connection must not fail.
func streamRequestViaConn(producer io.Reader, consumer func(net.Conn)) *bytes.Buffer {
	pr, pw := memconn.Pipe()
	defer pr.Close()
	defer pw.Close()
	var restOfReq bytes.Buffer
	consumerDone := make(chan struct{}, 1)
	go func() {
		must(io.Copy(pw, producer))
		<-consumerDone
		pw.Close()
	}()
	consumer(pr)
	consumerDone <- struct{}{}
	must(io.Copy(&restOfReq, pr))
	return &restOfReq
}

func checkRebuiltRequest(t *testing.T, original io.Reader, sniffer *Sniffer, restOfRequest *bytes.Buffer) {
	zeroLenMeansNil := func(s []byte) []byte {
		if len(s) == 0 {
			return nil
		}
		return s
	}

	var reqBytes bytes.Buffer
	must(io.Copy(&reqBytes, original))
	var reconstructedReq bytes.Buffer
	must(sniffer.GetBufferedData().WriteTo(&reconstructedReq))
	must(io.Copy(&reconstructedReq, restOfRequest))
	require.Equal(t, zeroLenMeansNil(reqBytes.Bytes()), zeroLenMeansNil(reconstructedReq.Bytes()))
}

func tableTestHelper[TD testDataInterface](t *testing.T, snifferFactory func() *Sniffer, testData []TD) {
	for _, scenario := range testData {
		t.Run(scenario.GetDescription(), func(t *testing.T) {
			sniffer := snifferFactory()
			reqReader := scenario.ReaderForRequest()
			var hostname string
			var err error
			restOfRequest := streamRequestViaConn(reqReader, func(c net.Conn) {
				hostname, err = sniffer.SniffHostName(c)
			})
			scenario.ErrorCheck(t, err)
			scenario.HostnameCheck(t, hostname)
			checkRebuiltRequest(t, scenario.ReaderForRequest(), sniffer, restOfRequest)
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

func TestParallelSnifferWithASuccessfulAndAFailingStub(t *testing.T) {
	expectedHost := "www.example.com"
	sniffStrategyStubOK := func(c io.Reader) (string, error) {
		return expectedHost, nil
	}
	sniffStrategyStubFail := func(c io.Reader) (string, error) {
		return "", fmt.Errorf("stub strategy always fails")
	}

	stubOK := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStubOK))
	stubKO := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStubFail))
	sniffer := NewParallelSniffer(
		WithParallelSnifferStrategy(stubOK),
		WithParallelSnifferStrategy(stubKO),
	)
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

func TestParallelSnifferWithMaxDataExceeded(t *testing.T) {
	sniffStrategyStub := func(c io.Reader) (string, error) {
		io.Copy(io.Discard, c)
		return "", fmt.Errorf("stub strategy failed")
	}

	const testMaxData = 16
	const testMaxTime = time.Minute
	testBytes := make([]byte, testMaxData)
	stub := NewSniffStrategyFromInterface(snifferStrategyFunction(sniffStrategyStub))
	sniffer := NewParallelSniffer(
		WithParallelSnifferStrategy(stub),
		// Give the test some time to complete. Under extreme load, the timeout
		// could be triggered before the data limit is reached. There is no way
		// around this unless the timeout can be se to infinity, which is
		// currently not the case.
		WithParallelTimeout(testMaxTime),
		WithParallelMaxData(testMaxData),
	)
	var hostname string
	var err error

	before := time.Now()
	restOfRequest := streamRequestViaConn(bytes.NewReader(testBytes), func(c net.Conn) {
		hostname, err = sniffer.SniffHostName(c)
	})
	after := time.Now()
	require.Less(t, after.Sub(before), testMaxTime)
	require.Empty(t, hostname)
	require.ErrorIs(t, errTimeoutOrDataLimitExceeded, err)
	checkRebuiltRequest(t, bytes.NewReader(testBytes), sniffer, restOfRequest)
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
