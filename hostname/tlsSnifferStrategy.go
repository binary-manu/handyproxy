package hostname

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	dissector "github.com/go-gost/tls-dissector"
)

func sniffHostNameFromTLSSNI(r io.Reader) (string, error) {

	var recordData bytes.Buffer
	for {
		rec, err := dissector.ReadRecord(r)
		if err != nil {
			return "", fmt.Errorf("unable to extract SNI from TLS stream: %w", err)
		}
		recordData.Write(rec.Opaque)

		var clientHello dissector.ClientHelloHandshake
		_, err = clientHello.ReadFrom(bytes.NewReader(recordData.Bytes()))
		if err == nil {
			for _, ext := range clientHello.Extensions {
				if sni, ok := ext.(*dissector.ServerNameExtension); ok {
					return sni.Name, nil
				}
			}
			return "", fmt.Errorf("unable to extract SNI from TLS stream: the SNI extension is absent")
		} else if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
			return "", fmt.Errorf("unable to extract SNI from TLS stream: %w", err)
		}
	}
}

func NewTLSSnifferStrategy() *SniffStrategy {
	return &SniffStrategy{snifferStrategyFunction(sniffHostNameFromTLSSNI)}
}
