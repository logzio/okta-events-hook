package handler

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandleRequest(t *testing.T) {
	jsonFile, err := os.Open(fmt.Sprintf("../testdata/sampleEvent.json"))
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

func TestSetListenerURL(t *testing.T) {
	type setListenerURLTest struct {
		region   string
		expected string
	}
	var setListenerURLTests = []setListenerURLTest{
		{"us", "https://listener.logz.io:8071"},
		{"eu", "https://listener-eu.logz.io:8071"},
		{"au", "https://listener-au.logz.io:8071"},
		{"ca", "https://listener-ca.logz.io:8071"},
		{"uk", "https://listener-uk.logz.io:8071"},
		{"not-valid", "https://listener.logz.io:8071"},
		{"", "https://listener.logz.io:8071"},
		{"US", "https://listener.logz.io:8071"},
		{"Us", "https://listener.logz.io:8071"},
	}

	for _, test := range setListenerURLTests {
		l := logzioClient{}
		l.setListenerURL(test.region)
		require.Equal(t, l.url, test.expected)
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
			url:        ts.URL,
			httpClient: &http.Client{},
			logsBuffer: bytes.Buffer{},
		}
		logzioClient.writeLog(data)
		assert.Equal(t, code, logzioClient.export())
		assert.Equal(t, 0, logzioClient.logsBuffer.Len())
		ts.Close()
	}
}
