package hostname

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/stretchr/testify/require"
)

type testDataInterface interface {
	HostnameCheck(require.TestingT, any, ...any)
	ErrorCheck(require.TestingT, error, ...any)
	ReaderForRequest() io.Reader
	GetDescription() string
}

type testData struct {
	Description     string
	Request         string
	HostnameChecker func(require.TestingT, any, ...any)
	ErrorChecker    func(require.TestingT, error, ...any)
}

func (td *testData) HostnameCheck(t require.TestingT, v any, args ...any) {
	td.HostnameChecker(t, v, args)
}

func (td *testData) ErrorCheck(t require.TestingT, e error, args ...any) {
	td.ErrorChecker(t, e, args)
}

func (td *testData) ReaderForRequest() io.Reader {
	return strings.NewReader(td.Request)
}

func (td *testData) GetDescription() string {
	return td.Description
}

type testDataHexRequest struct {
	*testData
}

func (td *testDataHexRequest) ReaderForRequest() io.Reader {
	return hex.NewDecoder(td.testData.ReaderForRequest())
}

func withExpected(expected any) func(require.TestingT, any, ...any) {
	return func(t require.TestingT, actual any, args ...any) {
		require.Equal(t, expected, actual, args)
	}
}

func must[T any](res T, err error) T {
	if err != nil {
		panic(fmt.Errorf("unexpected error in test setup: %w", err))
	}
	return res
}
