package hostname

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNullSniffer(t *testing.T) {
	sniffer := NewNullSniffer()
	hostname, err := sniffer.SniffHostName(nil)
	require.Empty(t, hostname)
	require.Error(t, err)
	var bufferedData bytes.Buffer
	require.NotNil(t, sniffer.GetBufferedData())
	sniffer.GetBufferedData().WriteTo(&bufferedData)
	require.Equal(t, 0, bufferedData.Len())
}
