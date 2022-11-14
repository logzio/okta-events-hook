package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/logzio/okta-events-hook/handler"
)

func main() {
	lambda.Start(handler.HandleRequest)
}
