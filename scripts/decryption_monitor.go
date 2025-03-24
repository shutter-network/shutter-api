package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

type RegisterIdentityRequest struct {
	DecryptionTimestamp int64  `json:"decryptionTimestamp"`
	IdentityPrefix      string `json:"identityPrefix"`
}

type DecryptionStats struct {
	totalDecryptions   atomic.Int64
	validDecryptions   atomic.Int64
	invalidDecryptions atomic.Int64
}

var (
	stats    DecryptionStats
	stopChan = make(chan os.Signal, 1)
)

type BaseResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type RegisterIdentityResponse struct {
	Eon            uint64 `json:"eon"`
	Identity       string `json:"identity"`
	IdentityPrefix string `json:"identity_prefix"`
	EonKey         string `json:"eon_key"`
	TxHash         string `json:"tx_hash"`
}

type GetDecryptionKeyResponse struct {
	DecryptionKey       string `json:"decryption_key"`
	Identity            string `json:"identity"`
	DecryptionTimestamp uint64 `json:"decryption_timestamp"`
}

type GetDataForEncryptionResponse struct {
	Eon            uint64 `json:"eon"`
	Identity       string `json:"identity"`
	IdentityPrefix string `json:"identity_prefix"`
	EonKey         string `json:"eon_key"`
	EpochID        string `json:"epoch_id"`
}

type ErrorResponse struct {
	Description string `json:"description,omitempty"`
	Metadata    string `json:"metadata,omitempty"`
	StatusCode  int    `json:"statusCode"`
}

func main() {
	baseURL := os.Getenv("API_URL")
	interval := 1 * time.Minute
	testAddress := "0x228DefCF37Da29475F0EE2B9E4dfAeDc3b0746bc"

	fmt.Printf("Starting performance monitoring\n")
	fmt.Printf("Base URL: %s\n", baseURL)
	fmt.Printf("Interval: %v\n\n", interval)

	// Setup graceful shutdown
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start monitoring in separate goroutine
	go func() {
		runFlow(baseURL, testAddress, &wg)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				runFlow(baseURL, testAddress, &wg)
			case <-stopChan:
				return
			}
		}
	}()

	// Wait for interrupt signal
	<-stopChan
	fmt.Printf("\nShutting down...\n")

	// Wait for all decryption requests to complete
	wg.Wait()

	// Print final statistics
	printStatistics()
}

func printStatistics() {
	fmt.Printf("\n=== Final Decryption Statistics ===\n")
	fmt.Printf("Total decryption attempts: %d\n", stats.totalDecryptions.Load())
	fmt.Printf("Successful decryptions: %d\n", stats.validDecryptions.Load())
	fmt.Printf("Failed decryptions: %d\n", stats.invalidDecryptions.Load())

	total := stats.totalDecryptions.Load()
	if total > 0 {
		successRate := float64(stats.validDecryptions.Load()) / float64(total) * 100
		fmt.Printf("Success rate: %.2f%%\n", successRate)
	}
}

func runFlow(baseURL, address string, wg *sync.WaitGroup) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("\n=== Performance Check at %s ===\n", timestamp)

	encryptionData, err := getDataForEncryption(baseURL, address, "")
	if err != nil {
		log.Err(err).Msg("error in get data for encryption endpoint")
		return
	}

	decryptionTime := time.Now().Add(20 * time.Second)
	registerReq := RegisterIdentityRequest{
		DecryptionTimestamp: decryptionTime.Unix(),
		IdentityPrefix:      encryptionData["message"].IdentityPrefix,
	}

	err = registerIdentity(baseURL, registerReq)
	if err != nil {
		log.Err(err).Msg("error encountered while registering identity")
		return
	}

	// Launch decryption key request in separate goroutine
	wg.Add(1)
	go func(identity string, decryptTime time.Time) {
		defer wg.Done()
		waitDuration := time.Until(decryptTime.Add(2 * time.Second))

		time.Sleep(waitDuration)
		stats.totalDecryptions.Add(1)
		err := getDecryptionKey(baseURL, identity)
		if err != nil {
			log.Err(err).Msg("error encountered while get decryption key")
			stats.invalidDecryptions.Add(1)
			return
		}

		stats.validDecryptions.Add(1)
	}(encryptionData["message"].Identity, decryptionTime)
}

func getDataForEncryption(baseURL, address, identityPrefix string) (map[string]GetDataForEncryptionResponse, error) {
	params := url.Values{}
	params.Add("address", address)
	if identityPrefix != "" {
		params.Add("identityPrefix", identityPrefix)
	}

	url := fmt.Sprintf("%s/get_data_for_encryption?%s", baseURL, params.Encode())
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, err

	}

	var response map[string]GetDataForEncryptionResponse

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse  response: %v", err)
	}

	return response, nil
}

func registerIdentity(baseURL string, req RegisterIdentityRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(
		baseURL+"/register_identity",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return fmt.Errorf("failed to parse error response: %v", err)
		}
		return fmt.Errorf("response error %v", errorResp.Description)
	}

	return nil
}

func getDecryptionKey(baseURL, identity string) error {
	params := url.Values{}
	params.Add("identity", identity)

	url := fmt.Sprintf("%s/get_decryption_key?%s", baseURL, params.Encode())
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp ErrorResponse
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return fmt.Errorf("failed to parse error response, %v", err)
		}
		return fmt.Errorf("failed to parse error response, %s", errorResp.Description)
	}
	return nil
}
