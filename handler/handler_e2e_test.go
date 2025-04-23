package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// LogResponse models the shape of a Logz.io search response for our fields
type LogResponse struct {
	Hits struct {
		Total int `json:"total"`
		Hits  []struct {
			Source struct {
				Type      string `json:"type"`
				EventType string `json:"eventType"`
				EventID   string `json:"eventId"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

const (
	BaseLogzioApiUrl = "https://api.logz.io/v1"
	QueryTemplate    = `{
  "query": {
    "query_string": {
      "query": "{{QUERY}}"
    }
  },
  "from": 0,
  "size": 100,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "_source": true,
  "docvalue_fields": [
    "@timestamp"
  ],
  "version": true,
  "stored_fields": [
    "*"
  ],
  "highlight": {},
  "aggregations": {
    "byType": {
      "terms": {
        "field": "type",
        "size": 5
      }
    }
  }
}`
)

func formatQuery(query string) string {
	return strings.Replace(QueryTemplate, "{{QUERY}}", query, 1)
}

func fetchLogs(apiToken, baseURL, query string) (*LogResponse, error) {
	url := fmt.Sprintf("%s/search", baseURL)
	formattedQuery := formatQuery(query)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(formattedQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-TOKEN", apiToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var lr LogResponse
	err = json.Unmarshal(data, &lr)
	if err != nil {
		return nil, err
	}
	return &lr, nil
}

func TestE2EHandleRequest(t *testing.T) {
	shippingToken := os.Getenv("LOGZIO_LOGS_TOKEN")
	if shippingToken == "" {
		t.Skip("LOGZIO_LOGS_TOKEN not set; skipping E2E test")
	}
	apiToken := os.Getenv("LOGZIO_API_TOKEN")
	if apiToken == "" {
		t.Skip("LOGZIO_API_TOKEN not set; skipping E2E test")
	}
	raw, err := os.ReadFile("../testdata/sampleEvent.json")
	require.NoError(t, err)

	var evt map[string]interface{}
	err = json.Unmarshal(raw, &evt)
	require.NoError(t, err)
	for _, e := range evt["data"].(map[string]interface{})["events"].([]interface{}) {
		event := e.(map[string]interface{})
		event["published"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	uniqueId := uuid.New().String()
	evt["eventId"] = uniqueId
	payload, err := json.Marshal(evt)
	require.NoError(t, err)

	req := events.APIGatewayProxyRequest{
		HTTPMethod: "POST",
		Body:       string(payload),
		Headers: map[string]string{
			"logzio_token":  shippingToken,
			"logzio_region": "us",
		},
	}
	resp, err := HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	t.Log("waiting for logs to be indexed...")
	time.Sleep(120 * time.Second)

	eType, _ := evt["eventType"].(string)
	query := fmt.Sprintf("type:okta AND eventType:%s AND eventId:%s", eType, uniqueId)

	lr, err := fetchLogs(apiToken, BaseLogzioApiUrl, query)
	require.NoError(t, err)
	assert.Greater(t, lr.Hits.Total, 0, "expected at least one log hit")
}
