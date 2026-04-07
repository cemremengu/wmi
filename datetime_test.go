package wmi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseWMIDateTime(t *testing.T) {
	dt, ok := ParseWMIDateTime("20220207094949.500000+060").(time.Time)
	require.True(t, ok && dt.Format(time.RFC3339Nano) == "2022-02-07T09:49:49.5+01:00", "unexpected datetime: %#v", dt)
	require.Equal(t, "2022-02-07 09:49:49+060", FormatWMIDateTime(dt))

	dt, ok = ParseWMIDateTime("19980525133015.0000000-300").(time.Time)
	require.True(t, ok && dt.Format(time.RFC3339) == "1998-05-25T13:30:15-05:00", "unexpected datetime: %#v", dt)

	dt, ok = ParseWMIDateTime("19980525******.0000000+000").(time.Time)
	require.True(t, ok && dt.Format(time.RFC3339) == "1998-05-25T00:00:00Z", "unexpected wildcard datetime: %#v", dt)
}

func TestUUIDRoundTrip(t *testing.T) {
	raw, err := uuidToBin("9556DC99-828C-11CF-A37E-00AA003240C7")
	require.NoError(t, err)
	require.Equal(t, "9556DC99-828C-11CF-A37E-00AA003240C7", binToUUID(raw, 0))
}
