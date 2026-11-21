package usecase

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gotest.tools/assert"
)

func TestKeyperFallbackAllHangBoundedPerKeyper(t *testing.T) {
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+hangingServer(t).URL+","+hangingServer(t).URL)
	uc.keyperFailoverTimeout = 100 * time.Millisecond
	uc.keyperRequestTimeout = time.Second

	start := time.Now()
	key, err := queryWithin(t, uc, 5*time.Second)
	elapsed := time.Since(start)

	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.ErrorContains(t, err, "context deadline exceeded")
	assert.Equal(t, key, "")
	// The first two keypers get 100ms each and the last one 1s, so 1.2s in
	// all, with 300ms of room for a slow test machine. Giving all three
	// keypers 100ms, or all three 1s, or swapping the two bounds, lands
	// outside this range.
	assert.Assert(t, elapsed >= 1200*time.Millisecond, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 1500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackCancelledRequestStopsWaiting(t *testing.T) {
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+hangingServer(t).URL)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	key, err := uc.getDecryptionKeyFromExternalKeyper(ctx, 1, "0x01")
	elapsed := time.Since(start)

	assert.ErrorContains(t, err, "context deadline exceeded")
	assert.Equal(t, key, "")
	assert.Assert(t, elapsed < 2*time.Second, "returned after %s", elapsed)
}

func TestKeyperFallbackCancelledRequestAsksNoFurtherKeyper(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previous })
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+hangingServer(t).URL+","+hangingServer(t).URL)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	key, err := uc.getDecryptionKeyFromExternalKeyper(ctx, 1, "0x01")

	assert.ErrorContains(t, err, "context deadline exceeded")
	assert.Equal(t, key, "")
	// Only the keyper that was being asked when the caller ran out of time
	// is reported, not the ones after it that were never really asked.
	warnings := strings.Count(logs.String(), "failed to get decryption key from fallback keyper")
	assert.Equal(t, warnings, 1, "log: %s", logs.String())
}

func TestKeyperFallbackAllFailReturnsFirstKeyperError(t *testing.T) {
	// The first keyper refuses the connection and the second one times out.
	// The error returned is the first keyper's, as it was with one keyper,
	// and not the error from the last keyper asked.
	first := downURL(t)
	second := hangingServer(t).URL
	uc := newFallbackTestUsecase(t, first+","+second)
	uc.keyperRequestTimeout = 200 * time.Millisecond

	key, err := queryWithin(t, uc, 5*time.Second)

	assert.Equal(t, key, "")
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.ErrorContains(t, err, strings.TrimPrefix(first, "http://"))
	assert.Assert(t, !strings.Contains(err.Error(), strings.TrimPrefix(second, "http://")), "error: %v", err)
	assert.Assert(t, !strings.Contains(err.Error(), "context deadline exceeded"), "error: %v", err)
}
