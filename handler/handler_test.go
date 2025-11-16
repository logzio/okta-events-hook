package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleRequest(t *testing.T) {
	jsonFile, err := os.Open("../testdata/sampleEvent.json")
	if err != nil {
		fmt.Println(err)
	}
	byteValue, _ := io.ReadAll(jsonFile)
	if err != nil {
		t.Error(err)
	}
	ctx := context.Background()
	headers := make(map[string]string)
	headers["logzio_token"] = "token"
	headers["logzio_region"] = "us"
	headers["x-okta-request-id"] = "Y3J0sjoXfBZ536qdqnkabwAAA58"
	request := events.APIGatewayProxyRequest{
		HTTPMethod:      "POST",
		RequestContext:  events.APIGatewayProxyRequestContext{},
		Body:            string(byteValue),
		Headers:         headers,
		IsBase64Encoded: false,
	}
	response, err := HandleRequest(ctx, request)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(response)
}

func TestCheckOktaNewEndpointValidation(t *testing.T) {
	headers := make(map[string]string)
	headers["x-okta-verification-challenge"] = "value"
	request := events.APIGatewayProxyRequest{
		HTTPMethod:      "POST",
		RequestContext:  events.APIGatewayProxyRequestContext{},
		Headers:         headers,
		IsBase64Encoded: false,
	}
	response := CheckOktaNewEndpointValidation(request)
	assert.NotNil(t, response.Body)
}

func TestGetCredentialsFromHeaders(t *testing.T) {
	type getCredentialsFromHeadersTest struct {
		token         string
		region        string
		expectedError bool
	}
	var getCredentialsFromHeadersTests = []getCredentialsFromHeadersTest{
		{"validbIyXnVFJAhojiALQuKzOmQtoken", "us", false},
		{"token", "us", true},
		{"token", "ewr", true},
		{"validbIyXnVFJAhojiALQuKzOmQtoken", "not-valid", true},
		{"", "", true},
		{"validbIyXnVFJAhojiALQuKzOmQtoken", "", true},
		{"", "us", true},
	}

	for _, test := range getCredentialsFromHeadersTests {
		headers := make(map[string]string)
		headers["logzio_token"] = test.token
		headers["logzio_region"] = test.region
		_, _, err := getCredentialsFromHeaders(headers)
		if test.expectedError {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestSetRegion(t *testing.T) {
	type setRegionTest struct {
		region      string
		expectedURL string
		expectedErr bool
	}
	var setRegionTests = []setRegionTest{
		{"us", "https://listener.logz.io:8071", false},
		{"eu", "https://listener-eu.logz.io:8071", false},
		{"au", "https://listener-au.logz.io:8071", false},
		{"ca", "https://listener-ca.logz.io:8071", false},
		{"uk", "https://listener-uk.logz.io:8071", false},
		{"not-valid", "https://listener.logz.io:8071", false}, // defaults to "us"
		{"", "https://listener.logz.io:8071", false},          // defaults to "us"
		{"US", "https://listener.logz.io:8071", false},        // case insensitive
		{"Us", "https://listener.logz.io:8071", false},        // case insensitive
	}

	for _, test := range setRegionTests {
		l := logzioClient{}
		err := l.setRegion(test.region)
		if test.expectedErr {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
			// For invalid regions, it defaults to "us", so check the expected region
			expectedRegion := strings.ToLower(test.region)
			if expectedRegion != "us" && expectedRegion != "eu" && expectedRegion != "au" && expectedRegion != "ca" && expectedRegion != "uk" {
				expectedRegion = "us" // Invalid regions default to "us"
			}
			require.Equal(t, expectedRegion, l.region)
			// Verify getFullURL returns the expected URL (without token)
			fullURL, err := l.getFullURL()
			if err == nil {
				// Extract base URL without query params for comparison
				require.Contains(t, fullURL, test.expectedURL)
			}
		}
	}
}

func TestShouldRetry(t *testing.T) {
	type shouldRetryTest struct {
		statusCode int
		expected   bool
	}
	var shouldRetryTests = []shouldRetryTest{
		{400, false},
		{404, false},
		{403, false},
		{200, false},
		{401, false},
		{500, true},
		{987, true},
	}
	logzioClient := logzioClient{}
	for _, test := range shouldRetryTests {
		sr := logzioClient.shouldRetry(test.statusCode)
		assert.Equal(t, test.expected, sr)
	}
}

func TestExport(t *testing.T) {
	codes := []int{413, 400, 500, 200, 403, 404}
	for _, code := range codes {
		// Test server
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		ts.Start()
		data := make([]byte, 100)
		logzioClient := logzioClient{
			token:      "token",
			testURL:    ts.URL, // Use testURL for testing purposes
			httpClient: &http.Client{},
			logsBuffer: bytes.Buffer{},
		}
		logzioClient.writeLog(data)
		assert.Equal(t, code, logzioClient.export())
		assert.Equal(t, 0, logzioClient.logsBuffer.Len())
		ts.Close()
	}
}

func TestSSRFProtection(t *testing.T) {
	t.Run("rejects invalid region not in safelist", func(t *testing.T) {
		client := logzioClient{
			token:      "testtoken",
			region:     "malicious-region",
			httpClient: &http.Client{},
			logsBuffer: bytes.Buffer{},
		}
		client.writeLog("test")
		// Should return error status because region is not in safelist
		statusCode := client.makeHttpRequest(bytes.Buffer{})
		assert.Equal(t, http.StatusInternalServerError, statusCode)
	})

	t.Run("rejects empty region", func(t *testing.T) {
		client := logzioClient{
			token:      "testtoken",
			region:     "",
			httpClient: &http.Client{},
			logsBuffer: bytes.Buffer{},
		}
		client.writeLog("test")
		statusCode := client.makeHttpRequest(bytes.Buffer{})
		assert.Equal(t, http.StatusInternalServerError, statusCode)
	})

	t.Run("allows only safelist regions", func(t *testing.T) {
		validRegions := []string{"us", "eu", "au", "ca", "uk"}
		for _, region := range validRegions {
			client := logzioClient{
				token:      "testtoken",
				region:     region,
				httpClient: &http.Client{},
				logsBuffer: bytes.Buffer{},
			}
			// getFullURL should succeed for valid regions
			fullURL, err := client.getFullURL()
			assert.NoError(t, err, "region %s should be valid", region)
			assert.Contains(t, fullURL, "listener")
			assert.Contains(t, fullURL, "logz.io")
		}
	})

	t.Run("rejects non-https scheme for production URLs", func(t *testing.T) {
		client := logzioClient{
			token:      "testtoken",
			region:     "us",
			httpClient: &http.Client{},
			logsBuffer: bytes.Buffer{},
		}
		// getFullURL should return https URLs
		fullURL, err := client.getFullURL()
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(fullURL, "https://"), "URL should use https scheme")
	})
}
