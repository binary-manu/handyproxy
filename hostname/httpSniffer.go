package hostname

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
)

func httpHostNameSniffer(r io.Reader) (string, error) {
	req, err := http.ReadRequest(bufio.NewReader(r))
	if err != nil {
		return "", fmt.Errorf("unable to parse HTTP request: %w", err)
	}
	if req.Host != "" {
		return req.Host, nil
	}
	return "", fmt.Errorf("HTTP Host header is missing")
}

func HTTPSniffer() HostNameSniffStrategy {
	return snifferFunction(httpHostNameSniffer)
}
