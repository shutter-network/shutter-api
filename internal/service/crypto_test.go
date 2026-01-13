package service

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sigparser "github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/common"
	hexutil "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gin-gonic/gin"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
	shcommon "github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/usecase"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.POST("/test", CompileEventTriggerDefinition)
	return router
}

func TestEventDecryptionValidation(t *testing.T) {
	router := setupRouter()
	testData := []string{
		// "grom" != "from"
		`{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "grom", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": 1}]}`,
		// "op": "gt" on "bytes" value (must be "number")
		`{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, address notify)","arguments": [{"name": "notify", "op": "gt", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"}]}`,
		// "op: gte" illegal on indexed address
		`{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "gte", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": 1}]}`,
		// argument "from" defined more than once
		`{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "from", "op": "eq", "value": "0x8e13976721ebff885611c8391d9b02749c1283fa"}]}`,
		// invalid JSON
		`{foo: "bar"}`,
		// missing contract address
		`{"eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": 1}]}`,
		// missing signature
		`{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": 1}]}`,
	}
	for _, bites := range testData {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/test", strings.NewReader(bites))
		router.ServeHTTP(w, req)
		assert.Check(t, w.Code != 200, "error returned 200")
	}
}

func TestEventDecryptionData(t *testing.T) {
	router := setupRouter()
	bites := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": 1}]}`
	w := httptest.NewRecorder()
	fromAsBytes, err := hexutil.Decode("0x9e13976721ebff885611c8391d9b02749c1283fa")
	assert.NilError(t, err, "hex decode failed")
	var req usecase.EventTriggerDefinitionRequest
	err = json.NewDecoder(strings.NewReader(bites)).Decode(&req)
	assert.NilError(t, err, "invalid json")
	sig, err := sigparser.ParseSignature(req.EventSignature)
	g := shs.EventTriggerDefinition{
		Contract: common.HexToAddress("0x4D6dD1382AA09be1d243F8960409A1ab3d913F43"),
		LogPredicates: []shs.LogPredicate{
			usecase.Topic0(sig),
			{
				LogValueRef: shs.LogValueRef{
					Offset: 1,
					Length: 1,
				},
				ValuePredicate: shs.ValuePredicate{
					Op:       shs.BytesEq,
					ByteArgs: [][]byte{usecase.Align(fromAsBytes)},
				},
			},
			{
				LogValueRef: shs.LogValueRef{
					Offset: 4,
					Length: 1,
				},
				ValuePredicate: shs.ValuePredicate{
					Op:      shs.UintGte,
					IntArgs: []*big.Int{big.NewInt(1)},
				},
			},
		},
	}

	etd := usecase.EventTriggerDefinitionResponse{
		EventTriggerDefinition: shcommon.PrefixWith0x(hex.EncodeToString(g.MarshalBytes())),
	}
	expected, err := json.Marshal(etd)
	assert.NilError(t, err, "error marshalling")

	request, _ := http.NewRequest("POST", "/test", strings.NewReader(bites))
	router.ServeHTTP(w, request)

	assert.Equal(t, 200, w.Code)
	require.JSONEq(t, string(expected), w.Body.String(), "roundtrip failed")
}
