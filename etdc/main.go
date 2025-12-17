package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/shutter-network/shutter-api/internal/service"
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
	data, errors := service.CompileEventTriggerDefinitionInternal(req)
	if len(errors) > 0 {
		log.Fatal(errors)
	}
	fmt.Println(data.EventTriggerDefinition)
}

func IngestRequest() (service.EventTriggerDefinitionRequest, error) {
	var record service.EventTriggerDefinitionRequest
	err := json.NewDecoder(os.Stdin).Decode(&record)
	return record, err
}
