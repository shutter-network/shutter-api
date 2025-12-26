package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/shutter-network/shutter-api/internal/usecase"
)

// simple commandline compiler for EventTriggerDefinitions
// build from root folder via
//
// go build -ldflags '-w -s' -o bin/etdc ./etdc
//
// Usage:
// ```
// # given request.json
//
//	{
//		"contract": "0x953A0425ACCee2E05f22E78999c595eD2eE7183c",
//		"eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)",
//		"arguments": [
//			{"name": "from", "op": "eq", "bytes": "0x812a6755975485C6E340F97dE6790B34a94D1430"},
//			{"name": "amount", "op": "gte", "number": 2}]
//	}
//
// # you can call
// cat request.json | ./etdc
// # to compile
func main() {
	req, err := IngestRequest()
	if err != nil {
		log.Fatal(err)
	}
	data, errors := usecase.CompileEventTriggerDefinitionInternal(req)
	if len(errors) > 0 {
		log.Fatal(errors)
	}
	fmt.Println(data.EventTriggerDefinition)
}

func IngestRequest() (usecase.EventTriggerDefinitionRequest, error) {
	var record usecase.EventTriggerDefinitionRequest
	err := json.NewDecoder(os.Stdin).Decode(&record)
	return record, err
}
