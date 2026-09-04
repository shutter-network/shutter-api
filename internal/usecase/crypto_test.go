package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"gotest.tools/assert"
)

func newTransactionSubmissionTestUsecase(timeout time.Duration) *CryptoUsecase {
	return &CryptoUsecase{
		sendSem:                      semaphore.NewWeighted(1),
		transactionSubmissionTimeout: timeout,
	}
}

func TestSubmitTransactionSerializesConcurrentSubmissions(t *testing.T) {
	uc := newTransactionSubmissionTestUsecase(2 * time.Second)
	const (
		firstSubmission  = 1
		secondSubmission = 2
	)

	transactionSubmissionStarted := make(chan int, 2)
	finishFirstSubmission := make(chan struct{})
	var submissions errgroup.Group

	runSubmission := func(submissionID int) error {
		_, httpErr, err := uc.submitTransaction(context.Background(), func(context.Context) (*types.Transaction, error) {
			transactionSubmissionStarted <- submissionID
			if submissionID == firstSubmission {
				<-finishFirstSubmission
			}
			return nil, nil
		})
		if httpErr != nil {
			return fmt.Errorf("submission %d returned HTTP %d", submissionID, httpErr.StatusCode)
		}
		if err != nil {
			return fmt.Errorf("submission %d failed: %w", submissionID, err)
		}
		return nil
	}

	submissions.Go(func() error { return runSubmission(firstSubmission) })
	assert.Equal(t, <-transactionSubmissionStarted, firstSubmission)

	submissions.Go(func() error { return runSubmission(secondSubmission) })
	select {
	case submissionID := <-transactionSubmissionStarted:
		close(finishFirstSubmission)
		t.Fatalf("submission %d started while submission 1 was still running", submissionID)
	case <-time.After(50 * time.Millisecond):
		// Submission 2 is correctly waiting for submission 1.
	}

	close(finishFirstSubmission)
	select {
	case submissionID := <-transactionSubmissionStarted:
		assert.Equal(t, submissionID, secondSubmission)
	case <-time.After(time.Second):
		t.Fatal("submission 2 did not start after submission 1 finished")
	}

	assert.NilError(t, submissions.Wait())
}

func TestSubmitTransactionTimeoutReleasesSemaphore(t *testing.T) {
	uc := newTransactionSubmissionTestUsecase(50 * time.Millisecond)

	_, httpErr, err := uc.submitTransaction(context.Background(), func(ctx context.Context) (*types.Transaction, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	assert.Assert(t, httpErr == nil)
	assert.Equal(t, err, context.DeadlineExceeded)

	nextSubmissionStarted := false
	_, httpErr, err = uc.submitTransaction(context.Background(), func(context.Context) (*types.Transaction, error) {
		nextSubmissionStarted = true
		return nil, nil
	})

	assert.NilError(t, err)
	assert.Assert(t, httpErr == nil)
	assert.Assert(t, nextSubmissionStarted)
}

// Test to verify that QueryExternalKeyper correctly trims quotes and newlines from the response body.
func TestGetDecryptionKeyFromExternalKeyper_QuotedBody(t *testing.T) {
	expectedKey := "0xdeadbeefcaffee"

	// Setup mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusOK)

		// this is how rolling-shutter http-api encodes the result
		json.NewEncoder(w).Encode(expectedKey)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)

	// Execute the function
	ctx := context.Background()
	result, err := QueryExternalKeyper(ctx, 1, "identity", parsedURL)

	assert.NilError(t, err, "QueryExternalKeyper errored", err)
	assert.Equal(t, result, expectedKey, "result not equal %v vs %v", result, expectedKey)
}
