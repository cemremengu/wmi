package wmi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDecodeBasicTypes(t *testing.T) {
	type Dst struct {
		Name      string `wmi:"Name"`
		ProcessID uint32 `wmi:"ProcessId"`
		Active    bool   `wmi:"Active"`
	}
	props := map[string]*Property{
		"Name":      {Name: "Name", Value: "explorer.exe"},
		"ProcessId": {Name: "ProcessId", Value: uint32(1234)},
		"Active":    {Name: "Active", Value: true},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "explorer.exe", d.Name)
	require.Equal(t, uint32(1234), d.ProcessID)
	require.True(t, d.Active)
}

func TestDecodeFieldNameFallback(t *testing.T) {
	type Dst struct {
		Caption string
		Version string
	}
	props := map[string]*Property{
		"Caption": {Name: "Caption", Value: "Windows 11"},
		"Version": {Name: "Version", Value: "10.0.22631"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "Windows 11", d.Caption)
	require.Equal(t, "10.0.22631", d.Version)
}

func TestDecodeSkipsTagDash(t *testing.T) {
	type Dst struct {
		Name    string `wmi:"Name"`
		Ignored string `wmi:"-"`
	}
	props := map[string]*Property{
		"Name":    {Name: "Name", Value: "foo"},
		"Ignored": {Name: "Ignored", Value: "should not appear"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "foo", d.Name)
	require.Empty(t, d.Ignored)
}

func TestDecodeNumericConversion(t *testing.T) {
	type Dst struct {
		Count int `wmi:"Count"`
	}
	props := map[string]*Property{
		"Count": {Name: "Count", Value: uint32(42)},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, 42, d.Count)
}

func TestDecodeTimeValue(t *testing.T) {
	type Dst struct {
		InstallDate time.Time `wmi:"InstallDate"`
	}
	now := time.Now().Truncate(time.Second)
	props := map[string]*Property{
		"InstallDate": {Name: "InstallDate", Value: now},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, now, d.InstallDate)
}

func TestDecodePointerField(t *testing.T) {
	type Dst struct {
		Name *string `wmi:"Name"`
	}
	props := map[string]*Property{
		"Name": {Name: "Name", Value: "test"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.NotNil(t, d.Name)
	require.Equal(t, "test", *d.Name)
}

func TestDecodeSkipsMissingAndNilProperties(t *testing.T) {
	type Dst struct {
		Name    string `wmi:"Name"`
		Missing string `wmi:"Missing"`
	}
	props := map[string]*Property{
		"Name": {Name: "Name", Value: "test"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "test", d.Name)
	require.Empty(t, d.Missing)
}

func TestDecodeErrorOnNonPointer(t *testing.T) {
	type Dst struct{ Name string }
	require.Error(t, Decode(nil, Dst{}))
}

func TestDecodeErrorOnNonStruct(t *testing.T) {
	s := "not a struct"
	require.Error(t, Decode(nil, &s))
}

func TestDecodeAll(t *testing.T) {
	type Proc struct {
		Name string `wmi:"Name"`
	}
	rows := []map[string]*Property{
		{"Name": {Name: "Name", Value: "proc1"}},
		{"Name": {Name: "Name", Value: "proc2"}},
	}
	var procs []Proc
	require.NoError(t, DecodeAll(rows, &procs))
	require.Len(t, procs, 2)
	require.Equal(t, "proc1", procs[0].Name)
	require.Equal(t, "proc2", procs[1].Name)
}

func TestDecodeAllPointerElements(t *testing.T) {
	type Proc struct {
		Name string `wmi:"Name"`
	}
	rows := []map[string]*Property{
		{"Name": {Name: "Name", Value: "proc1"}},
	}
	var procs []*Proc
	require.NoError(t, DecodeAll(rows, &procs))
	require.Len(t, procs, 1)
	require.Equal(t, "proc1", procs[0].Name)
}

func TestDecodeSliceField(t *testing.T) {
	type Dst struct {
		IPs []string `wmi:"IPs"`
	}
	props := map[string]*Property{
		"IPs": {Name: "IPs", Value: []any{"10.0.0.1", "10.0.0.2"}},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, d.IPs)
}

func TestDecodeTagWithOptions(t *testing.T) {
	type Dst struct {
		Name string `wmi:"Name,omitempty"`
	}
	props := map[string]*Property{
		"Name": {Name: "Name", Value: "test"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "test", d.Name)
}

func TestDecodeTagWithEmptyNameUsesFieldFallback(t *testing.T) {
	type Dst struct {
		Name string `wmi:",omitempty"`
	}
	props := map[string]*Property{
		"Name": {Name: "Name", Value: "test"},
	}
	var d Dst
	require.NoError(t, Decode(props, &d))
	require.Equal(t, "test", d.Name)
}

func TestDecodeRejectsOverflowingNumericConversion(t *testing.T) {
	type Dst struct {
		Small uint8 `wmi:"Small"`
	}
	props := map[string]*Property{
		"Small": {Name: "Small", Value: uint32(300)},
	}

	var d Dst
	require.Error(t, Decode(props, &d))
}
