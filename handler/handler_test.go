package handler

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"io/ioutil"
	"os"
	"testing"
)

func TestHandleRequest(t *testing.T) {
	jsonFile, err := os.Open(fmt.Sprintf("../testdata/sampleEvent.json"))
	if err != nil {
		fmt.Println(err)
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
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
