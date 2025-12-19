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
