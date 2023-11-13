package hostname

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"

	dissector "github.com/go-gost/tls-dissector"
	"github.com/stretchr/testify/require"
)

var tlsTestCompressionMethods []dissector.CompressionMethod = []dissector.CompressionMethod{0}

var tlsTestCipherSuites []dissector.CipherSuite = func() []dissector.CipherSuite {
	realSuites := tls.CipherSuites()
	testSuites := make([]dissector.CipherSuite, len(realSuites))
	for _, suite := range realSuites {
		testSuites = append(testSuites, dissector.CipherSuite(suite.ID))
	}
	return testSuites
}()

const tlsSNINameTypeHostName = 0
const tlsRecordContentTypeHandshake = 22

func makeHexStringFromClientHello(hello *dissector.ClientHelloHandshake, numRecords int) string {
	if numRecords < 1 {
		panic("number of TLS records must be >= 1")
	}

	// ClientHello message
	var helloBytes bytes.Buffer
	must(hello.WriteTo(&helloBytes))

	// Now break it into numRecords records
	var result strings.Builder
	msgSlice := helloBytes.Bytes()
	bytesPerRecord := len(msgSlice) / numRecords
	if bytesPerRecord == 0 {
		bytesPerRecord = 1
	}
	for len(msgSlice) > 0 {
		recSize := bytesPerRecord
		if bytesPerRecord > len(msgSlice) {
			recSize = len(msgSlice)
		}
		rec := dissector.Record{
			Version: tls.VersionTLS12,
			Type:    tlsRecordContentTypeHandshake,
			Opaque:  msgSlice[:recSize],
		}
		var recBytes bytes.Buffer
		must(rec.WriteTo(&recBytes))
		result.WriteString(hex.EncodeToString(recBytes.Bytes()))
		msgSlice = msgSlice[recSize:]
	}
	return result.String()
}

var tlsTestTable = []*testDataHexRequest{
	// Bad
	{&testData{
		"Empty request",
		"",
		require.Empty, require.Error,
	}},
	{&testData{
		"Short 1-byte ClientHello",
		"00",
		require.Empty, require.Error,
	}},
	{&testData{
		"Short 16-byte ClientHello",
		"00000000000000000000000000000000",
		require.Empty, require.Error,
	}},
	{&testData{
		"Real ClientHello, but without SNI, 1 record",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
			},
			1,
		),
		require.Empty, require.Error,
	}},
	{&testData{
		"Real ClientHello, but without SNI, ridicolously high number of records",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
			},
			1<<32-1,
		),
		require.Empty, require.Error,
	}},
	{&testData{
		"Real ClientHello, with SNI, 1 record",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
				Extensions: []dissector.Extension{&dissector.ServerNameExtension{
					NameType: tlsSNINameTypeHostName,
					Name:     "www.tlsname.test.com"}},
			},
			1,
		),
		withExpected("www.tlsname.test.com"), require.NoError,
	}},
	{&testData{
		"Real ClientHello, with SNI, 2 records",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
				Extensions: []dissector.Extension{&dissector.ServerNameExtension{
					NameType: tlsSNINameTypeHostName,
					Name:     "www.tlsname.test.com"}},
			},
			2,
		),
		withExpected("www.tlsname.test.com"), require.NoError,
	}},
	{&testData{
		"Real ClientHello, with SNI, 16 records",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
				Extensions: []dissector.Extension{&dissector.ServerNameExtension{
					NameType: tlsSNINameTypeHostName,
					Name:     "www.tlsname.test.com"}},
			},
			16,
		),
		withExpected("www.tlsname.test.com"), require.NoError,
	}},
	{&testData{
		"Real ClientHello, with SNI, ridicolously high number of records",
		makeHexStringFromClientHello(
			&dissector.ClientHelloHandshake{
				Version:            tls.VersionTLS12,
				CipherSuites:       tlsTestCipherSuites,
				CompressionMethods: tlsTestCompressionMethods,
				Extensions: []dissector.Extension{&dissector.ServerNameExtension{
					NameType: tlsSNINameTypeHostName,
					Name:     "www.tlsname.test.com"}},
			},
			1<<32-1,
		),
		withExpected("www.tlsname.test.com"), require.NoError,
	}},
}

func TestTLSSniffStrategy(t *testing.T) {
	for _, test := range tlsTestTable {
		t.Run(test.Description, func(t *testing.T) {
			strategy := NewTLSSnifferStrategy()
			hostName, err := strategy.SniffHostName(test.ReaderForRequest())
			test.ErrorCheck(t, err)
			test.HostnameCheck(t, hostName)
		})
	}
}
