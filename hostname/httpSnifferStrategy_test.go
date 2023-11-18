package hostname

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeHTTPRequest(method, url, body string) string {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := must(http.NewRequest(method, url, reader))
	var reqBytes bytes.Buffer
	must(struct{}{}, req.Write(&reqBytes))
	return reqBytes.String()
}

var httpTestTable = []*testData{
	// Bad
	{
		"Empty request",
		"",
		require.Empty, require.Error,
	},
	{
		"GET request no Host header",
		"GET / HTTP/1.1\r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"GET request no Host header but other headers",
		"GET / HTTP/1.1\r\nAccept: text/plain\r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"GET request, misspelled Host header",
		"GET / HTTP/1.1\r\nHosts: www.example.com\r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"GET request, empty Host header",
		"GET / HTTP/1.1\r\nHost:\r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"GET request, empty Host header (with trailing space)",
		"GET / HTTP/1.1\r\nHost: \r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"GET request, truncated request",
		"GET / HTTP/1.",
		require.Empty, require.Error,
	},
	{
		"POST request, no Host header, empty body",
		"POST / HTTP/1.1\r\n\r\n",
		require.Empty, require.Error,
	},
	{
		"POST request, no Host header, with body",
		"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nDATA",
		require.Empty, require.Error,
	},
	{
		"POST request, no Host header, body longr than expected",
		"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nDATA",
		require.Empty, require.Error,
	},
	{
		"POST request, no Host header, truncated body",
		"POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\nDATA",
		require.Empty, require.Error,
	},
	// Good
	{
		"GET request, Host header",
		"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
		withExpected("www.example.com"), require.NoError,
	},
	{
		"GET request, Host header with port",
		"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n",
		withExpected("www.example.com:8080"), require.NoError,
	},
	{
		"POST request, Host header",
		"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
		withExpected("www.example.com"), require.NoError,
	},
	{
		"POST request, Host header and payload",
		"GET / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 4\r\n\r\nDATA",
		withExpected("www.example.com"), require.NoError,
	},
	{
		"HEAD request, Host header",
		"HEAD / HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
		withExpected("www.example.com"), require.NoError,
	},
	{
		"PUT request, Host header and payload",
		"PUT / HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 4\r\n\r\nDATA",
		withExpected("www.example.com"), require.NoError,
	},
	{
		"Real GET request from net/http",
		makeHTTPRequest("GET", "http://www.foo.bar:8080/my/page.htm", ""),
		withExpected("www.foo.bar:8080"), require.NoError,
	},
	{
		"Real POST request from net/http",
		makeHTTPRequest("POST", "http://www.foo.bar:8080/my/page.htm", "Sample payload"),
		withExpected("www.foo.bar:8080"), require.NoError,
	},
	{
		"Real PUT request from net/http",
		makeHTTPRequest("PUT", "http://www.foo.bar:8080/my/page.htm", "Sample payload"),
		withExpected("www.foo.bar:8080"), require.NoError,
	},
}

func TestHTTPSniffStrategy(t *testing.T) {
	for _, test := range httpTestTable {
		t.Run(test.Description, func(t *testing.T) {
			strategy := NewHTTPSnifferStrategy()
			hostName, err := strategy.SniffHostName(test.ReaderForRequest())
			test.ErrorCheck(t, err)
			test.HostnameCheck(t, hostName)
		})
	}
}
