package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type apiGatewayResponse struct {
	RequestId string `json:"requestId"`
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
}

type oktaVerificationResponse struct {
	Verification string `json:"verification"`
}

func ApiGatewayResponse(statusCode int, message string) events.APIGatewayProxyResponse {
	body := apiGatewayResponse{
		Timestamp: time.Now().Unix(),
		Message:   message,
	}
	jsonData, _ := json.Marshal(body)
	return events.APIGatewayProxyResponse{
		Body:       string(jsonData),
		StatusCode: statusCode,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		IsBase64Encoded:   false,
		MultiValueHeaders: map[string][]string{},
	}
}
func CheckOktaNewEndpointValidation(request events.APIGatewayProxyRequest) events.APIGatewayProxyResponse {
	// okta endpoint verification
	oktaVerification := request.Headers["x-okta-verification-challenge"]
	if oktaVerification != "" {
		data := oktaVerificationResponse{
			Verification: oktaVerification,
		}
		jsonData, _ := json.Marshal(data)
		return events.APIGatewayProxyResponse{
			Body:       string(jsonData),
			StatusCode: 200,
			Headers: map[string]string{
				"content-type": "application/json",
			},
			IsBase64Encoded: false,
		}
	}
	return events.APIGatewayProxyResponse{}
}

type logzioClient struct {
	token      string
	url        string
	httpClient *http.Client
	logsBuffer bytes.Buffer
}

const maxBulkSize = 10000000

func (l *logzioClient) makeHttpRequest(data bytes.Buffer) int {
	url := fmt.Sprintf("%s/?token=%s&type=okta-events", l.url, l.token)
	req, err := http.NewRequest("POST", url, &data)
	req.Header.Add("Content-Encoding", "gzip")
	log.Printf("Sending bulk of %v bytes\n", l.logsBuffer.Len())
	resp, err := l.httpClient.Do(req)
	if err != nil {
		log.Printf("Error sending logs to %s %s\n", url, err)
		return resp.StatusCode
	}
	defer resp.Body.Close()
	statusCode := resp.StatusCode
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
	}
	log.Printf("Response status code: %v \n", statusCode)
	return statusCode
}

// shouldRetry is responsible to decide weather to retry a http request based on the response status coed
func (l *logzioClient) shouldRetry(statusCode int) bool {
	retry := true
	switch statusCode {
	case http.StatusBadRequest:
		log.Printf("Got HTTP %d bad request, skip retry\n", statusCode)
		retry = false
	case http.StatusNotFound:
		log.Printf("Got HTTP %d not found, skip retry\n", statusCode)
		retry = false
	case http.StatusUnauthorized:
		log.Printf("Got HTTP %d unauthorized, check your logzio shipping token\n", statusCode)
		retry = false
	case http.StatusForbidden:
		log.Printf("Got HTTP %d forbidden, skip retry\n", statusCode)
		retry = false
	case http.StatusOK:
		retry = false
	}
	return retry
}

// export sends the data buffer bytes to logz.io
func (l *logzioClient) export() int {
	var statusCode int
	// gzip compress data before shipping
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	_, err := gzipWriter.Write(l.logsBuffer.Bytes())
	if err != nil {
		l.logsBuffer.Reset()
		compressedBuf.Reset()
		return http.StatusInternalServerError
	}
	// listener limitation 10mb
	if compressedBuf.Len() > maxBulkSize {
		log.Printf("Bulk size is larger than %d bytes, cancelling export", maxBulkSize)
		l.logsBuffer.Reset()
		compressedBuf.Reset()
		return http.StatusRequestEntityTooLarge
	}
	err = gzipWriter.Close()
	if err != nil {
		l.logsBuffer.Reset()
		compressedBuf.Reset()
		return http.StatusInternalServerError
	}
	// retry logic
	backOff := time.Second * 2
	sendRetries := 4
	toBackOff := false
	for attempt := 0; attempt < sendRetries; attempt++ {
		if toBackOff {
			log.Printf("Failed to send logs, trying again in %v\n", backOff)
			time.Sleep(backOff)
			backOff *= 2
		}
		statusCode = l.makeHttpRequest(compressedBuf)
		if l.shouldRetry(statusCode) {
			toBackOff = true
		} else {
			break
		}
	}
	// Send data to back up storage in case of shipping error that cannot be resolved
	if statusCode != 200 {
		log.Printf("Error sending logs, status code is: %d", statusCode)
	}
	// reset data buffers
	l.logsBuffer.Reset()
	compressedBuf.Reset()
	return statusCode
}

func (l *logzioClient) setListenerURL(region string) {
	var url string
	lowerCaseRegion := strings.ToLower(region)
	switch lowerCaseRegion {
	case "us":
		url = "https://listener.logz.io:8071"
	case "ca":
		url = "https://listener-ca.logz.io:8071"
	case "eu":
		url = "https://listener-eu.logz.io:8071"
	case "uk":
		url = "https://listener-uk.logz.io:8071"
	case "au":
		url = "https://listener-au.logz.io:8071"
	case "nl":
		url = "https://listener-nl.logz.io:8071"
	case "wa":
		url = "https://listener-wa.logz.io:8071"
	default:
		url = "https://listener.logz.io:8071"
	}
	l.url = url
}

func HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// okta endpoint verification
	response := CheckOktaNewEndpointValidation(request)
	if response.Body != "" {
		return response, nil
	}
	// get requestId to match firehose response requirements
	logzioToken := request.Headers["logzio_token"]
	logzioRegion := request.Headers["logzio_region"]
	log.Println("Starting to parse request body")
	var body map[string]interface{}
	err := json.Unmarshal([]byte(request.Body), &body)
	if err != nil {
		log.Printf("Error while unmarshalling request body: %s", err)
		return ApiGatewayResponse(500, "Error while unmarshalling request body:"), nil
	}

	// in case server side is sleeping - wait 10s instead of waiting for him to wake up
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	// Initialize logzioClient
	logzioClient := logzioClient{
		token:      logzioToken,
		httpClient: client,
		logsBuffer: bytes.Buffer{},
	}
	logzioClient.setListenerURL(logzioRegion)

	return ApiGatewayResponse(200, "Execution finished successfully"), nil
}
