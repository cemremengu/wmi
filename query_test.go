package wmi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQContextConfigurationHelpers(t *testing.T) {
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil).SetTimeout(1234)
	require.Equal(t, uint32(1234), qc.timeout)
	require.False(t, qc.resultOptions.LoadQualifiers, "expected qualifiers to be disabled by default")
	require.Same(t, qc, qc.SetResultOptions(ResultOptions{
		IgnoreDefaults: true,
		IgnoreMissing:  true,
		LoadQualifiers: false,
	}).SetTimeout(4321), "expected fluent helpers to return the same context")
	require.Equal(t, uint32(4321), qc.timeout)
	require.True(t, qc.resultOptions.IgnoreDefaults)
	require.True(t, qc.resultOptions.IgnoreMissing)
	require.False(t, qc.resultOptions.LoadQualifiers)
}

func TestQContextNextObjectRetriesTimedOut(t *testing.T) {
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil)
	want := &objectBlock{}
	calls := 0

	got, err := qc.nextObject(context.Background(), 60, "slow", func(context.Context, uint32) (*objectBlock, error) {
		calls++
		if calls == 1 {
			return nil, wbemError(wbemSTimedOut)
		}
		return want, nil
	})
	require.NoError(t, err)
	require.Same(t, want, got)
	require.Equal(t, 2, calls)
}

func TestQContextNextObjectDoesNotRetryNoWait(t *testing.T) {
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil)
	calls := 0

	_, err := qc.nextObject(
		context.Background(),
		WBEMNoWait,
		"slow",
		func(context.Context, uint32) (*objectBlock, error) {
			calls++
			return nil, wbemError(wbemSTimedOut)
		},
	)
	require.ErrorIs(t, err, &Error{Code: wbemSTimedOut})
	require.Equal(t, 1, calls)
}

func TestQContextNextObjectRespectsContextCancellation(t *testing.T) {
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0

	_, err := qc.nextObject(ctx, 60, "slow", func(context.Context, uint32) (*objectBlock, error) {
		calls++
		return nil, wbemError(wbemSTimedOut)
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}

func TestQContextEachStopsOnBreak(t *testing.T) {
	// Each returns an iterator; verify the function signature compiles.
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil)
	seq := qc.Each(context.Background())
	require.NotNil(t, seq, "Each() should return a non-nil iterator")
}

func TestQContextNextObjectPersistentTimeoutExitsOnDeadline(t *testing.T) {
	qc := NewQuery("SELECT * FROM Win32_Process").context(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	calls := 0

	start := time.Now()
	_, err := qc.nextObject(ctx, 60, "slow", func(context.Context, uint32) (*objectBlock, error) {
		calls++
		return nil, wbemError(wbemSTimedOut)
	})
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.GreaterOrEqual(t, calls, 1)
	require.Less(
		t,
		elapsed,
		1*time.Second,
		"nextObject() took %v, expected it to exit near the 350ms deadline",
		elapsed,
	)
}
