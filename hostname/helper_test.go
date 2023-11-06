package hostname

import (
	"fmt"

	"github.com/stretchr/testify/require"
)

func withExpected(expected any) func(require.TestingT, any, ...any) {
	return func(t require.TestingT, actual any, args ...any) {
		require.Equal(t, expected, actual, args)
	}
}

func must(_ any, err error) {
	if err != nil {
		panic(fmt.Errorf("unexpected error in test setup: %w", err))
	}
}
