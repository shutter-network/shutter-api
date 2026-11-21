package usecase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/shutter-network/shutter-api/common"
	"gotest.tools/assert"
)

const fallbackTestKey = "0x99a805fc26812c13041126b25e91eccf3de464d1df7a95d1edca8831a9ec02dd"

// newFallbackTestUsecase builds the usecase the way main.go does, from the raw
// KEYPER_HTTP_URL value, so the tests cover parsing as well as querying.
func newFallbackTestUsecase(t *testing.T, keyperHTTPURL string) *CryptoUsecase {
	t.Helper()
	signingKey, err := crypto.GenerateKey()
	assert.NilError(t, err)
	config, err := common.NewConfig(keyperHTTPURL, signingKey, nil)
	assert.NilError(t, err)
	return NewCryptoUsecase(nil, nil, nil, nil, nil, nil, config)
}

// keyServer answers every decryption key request the way the rolling-shutter
// keyper http api does: a JSON encoded hex string.
func keyServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if !strings.HasPrefix(r.URL.Path, "/decryptionKey/") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fallbackTestKey)
	}))
	t.Cleanup(server.Close)
	return server
}

// statusServer answers every request with the given status and no key.
func statusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server
}

// downURL returns the address of a server that has been shut down, so that
// connecting to it is refused.
func downURL(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()
	return url
}

// hangingServer accepts requests and never answers them until the test ends.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

// slowServer answers every request with the key after the given delay, or
// gives up when the request is cancelled first.
func slowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	key := keyServer(t, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
			key.Config.Handler.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// queryWithin runs the fallback query and fails the test if it does not return
// within limit, instead of hanging the test binary.
func queryWithin(t *testing.T, uc *CryptoUsecase, limit time.Duration) (string, error) {
	t.Helper()
	type result struct {
		key string
		err error
	}
	done := make(chan result, 1)
	go func() {
		key, err := uc.getDecryptionKeyFromExternalKeyper(context.Background(), 1, "0x01")
		done <- result{key, err}
	}()
	select {
	case r := <-done:
		return r.key, r.err
	case <-time.After(limit):
		t.Fatalf("keyper fallback query did not return within %s", limit)
		return "", nil
	}
}

func TestKeyperFallbackSingleURLAnswers(t *testing.T) {
	hits := &atomic.Int32{}
	server := keyServer(t, hits)
	uc := newFallbackTestUsecase(t, server.URL)

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
	assert.Equal(t, hits.Load(), int32(1))
}

func TestKeyperFallbackSingleURLDown(t *testing.T) {
	uc := newFallbackTestUsecase(t, downURL(t))

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.Equal(t, key, "")
}

func TestKeyperFallbackSingleURLNotFound(t *testing.T) {
	uc := newFallbackTestUsecase(t, statusServer(t, http.StatusNotFound).URL)

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, "")
}

func TestKeyperFallbackFirstDownSecondAnswers(t *testing.T) {
	server := keyServer(t, nil)
	uc := newFallbackTestUsecase(t, downURL(t)+","+server.URL)

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
}

func TestKeyperFallbackListWithSpacesAndTrailingComma(t *testing.T) {
	server := keyServer(t, nil)
	uc := newFallbackTestUsecase(t, " "+downURL(t)+" , "+server.URL+" ,")

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
}

func TestKeyperFallbackFirstHangsSecondAnswers(t *testing.T) {
	server := keyServer(t, nil)
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+server.URL)

	// A keyper with another one after it is given 2 seconds, so the second
	// keyper is asked after about 2 seconds, not after the 5 seconds the last
	// keyper is given. The upper limit leaves half a second for a slow test
	// machine, so a bound for the first keyper that is half a second or more
	// longer fails the test.
	start := time.Now()
	key, err := queryWithin(t, uc, 8*time.Second)
	elapsed := time.Since(start)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
	assert.Assert(t, elapsed >= 2*time.Second, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 2500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackLastSlowStillAnswers(t *testing.T) {
	// The first keyper hangs and the last one answers after 3 seconds. The
	// last keyper is given 5 seconds, so its key is served, 2 + 3 = 5 seconds
	// after the lookup started.
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+slowServer(t, 3*time.Second).URL)

	start := time.Now()
	key, err := queryWithin(t, uc, 7*time.Second)
	elapsed := time.Since(start)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
	assert.Assert(t, elapsed >= 5*time.Second, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 5500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackTwoHangWorstCase(t *testing.T) {
	uc := newFallbackTestUsecase(t, hangingServer(t).URL+","+hangingServer(t).URL)

	// When every keyper hangs, the lookup takes 2 seconds for the first
	// keyper and 5 seconds for the last one, 7 seconds in all.
	start := time.Now()
	key, err := queryWithin(t, uc, 10*time.Second)
	elapsed := time.Since(start)
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.Equal(t, key, "")
	assert.Assert(t, elapsed >= 7*time.Second, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 7500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackSingleURLSlowAnswers(t *testing.T) {
	// A single keyper is given 5 seconds, so one that answers after 3 seconds
	// is served as soon as it answers.
	uc := newFallbackTestUsecase(t, slowServer(t, 3*time.Second).URL)

	start := time.Now()
	key, err := queryWithin(t, uc, 8*time.Second)
	elapsed := time.Since(start)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
	assert.Assert(t, elapsed >= 3*time.Second, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 3500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackSingleURLHangs(t *testing.T) {
	uc := newFallbackTestUsecase(t, hangingServer(t).URL)

	// A single keyper is given 5 seconds. The upper limit leaves half a second
	// for a slow test machine, so a bound that is half a second or more longer
	// fails the test.
	start := time.Now()
	key, err := queryWithin(t, uc, 8*time.Second)
	elapsed := time.Since(start)
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.Equal(t, key, "")
	assert.Assert(t, elapsed >= 5*time.Second, "returned after %s", elapsed)
	assert.Assert(t, elapsed < 5500*time.Millisecond, "returned after %s", elapsed)
}

func TestKeyperFallbackTriedInOrder(t *testing.T) {
	firstHits := &atomic.Int32{}
	secondHits := &atomic.Int32{}
	first := keyServer(t, firstHits)
	second := keyServer(t, secondHits)
	uc := newFallbackTestUsecase(t, first.URL+","+second.URL)

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, fallbackTestKey)
	assert.Equal(t, firstHits.Load(), int32(1))
	assert.Equal(t, secondHits.Load(), int32(0))
}

func TestKeyperFallbackFirstWithoutKeySecondAnswers(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusBadGateway} {
		server := keyServer(t, nil)
		uc := newFallbackTestUsecase(t, statusServer(t, status).URL+","+server.URL)

		key, err := queryWithin(t, uc, 2*time.Second)
		assert.NilError(t, err, "first keyper answered %d", status)
		assert.Equal(t, key, fallbackTestKey, "first keyper answered %d", status)
	}
}

func TestKeyperFallbackAllDown(t *testing.T) {
	uc := newFallbackTestUsecase(t, downURL(t)+","+downURL(t)+","+downURL(t))

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.Equal(t, key, "")
}

func TestKeyperFallbackDownAndNotFound(t *testing.T) {
	// One keyper is down and the other answers that it has no key: the key is
	// reported as not found, as a single keyper answering 404 is today.
	uc := newFallbackTestUsecase(t, downURL(t)+","+statusServer(t, http.StatusNotFound).URL)

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.NilError(t, err)
	assert.Equal(t, key, "")
}

func TestKeyperFallbackEmptyValueAsBefore(t *testing.T) {
	// An unset KEYPER_HTTP_URL starts the api, and every fallback request
	// fails with the same error as before.
	uc := newFallbackTestUsecase(t, "")

	key, err := queryWithin(t, uc, 2*time.Second)
	assert.ErrorContains(t, err, "failed to get decryption key for eon 1 and identity 0x01 from keyper")
	assert.ErrorContains(t, err, "unsupported protocol scheme")
	assert.Equal(t, key, "")
}
