build:
	go build main.go

function:
	GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -o bootstrap main.go
	zip -r function.zip bootstrap