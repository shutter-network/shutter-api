package service

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

	assertTriggerDefinitionEquals := func(t *testing.T, body string, expected shs.EventTriggerDefinition) {
		t.Helper()

		etd := usecase.EventTriggerDefinitionResponse{
			EventTriggerDefinition: shcommon.PrefixWith0x(hex.EncodeToString(expected.MarshalBytes())),
		}
		expectedJSON, err := json.Marshal(etd)
		assert.NilError(t, err, "error marshalling")

		w := httptest.NewRecorder()
		request, _ := http.NewRequest("POST", "/test", strings.NewReader(body))
		router.ServeHTTP(w, request)

		assert.Equal(t, 200, w.Code)
		require.JSONEq(t, string(expectedJSON), w.Body.String(), "roundtrip failed")
	}

	t.Run("indexed from + amount", func(t *testing.T) {
		body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`
		fromAsBytes, err := hexutil.Decode("0x9e13976721ebff885611c8391d9b02749c1283fa")
		assert.NilError(t, err, "hex decode failed")
		var req usecase.EventTriggerDefinitionRequest
		err = json.NewDecoder(strings.NewReader(body)).Decode(&req)
		assert.NilError(t, err, "invalid json")
		sig, err := sigparser.ParseSignature(req.EventSignature)
		expected := shs.EventTriggerDefinition{
			Contract: common.HexToAddress("0x4D6dD1382AA09be1d243F8960409A1ab3d913F43"),
			LogPredicates: []shs.LogPredicate{
				usecase.Topic0(sig),
				{
					LogValueRef: shs.LogValueRef{Offset: 1, Length: 1},
					ValuePredicate: shs.ValuePredicate{
						Op:       shs.BytesEq,
						ByteArgs: [][]byte{usecase.Align(fromAsBytes)},
					},
				},
				{
					LogValueRef: shs.LogValueRef{Offset: 4, Length: 1},
					ValuePredicate: shs.ValuePredicate{
						Op:      shs.UintGte,
						IntArgs: []*big.Int{big.NewInt(1)},
					},
				},
			},
		}

		assertTriggerDefinitionEquals(t, body, expected)
	})

	t.Run("indexed to uses offset 2", func(t *testing.T) {
		body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 value)","arguments": [{"name": "to", "op": "eq", "bytes":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"}]}`
		toAsBytes, err := hexutil.Decode("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
		assert.NilError(t, err, "hex decode failed")
		var req usecase.EventTriggerDefinitionRequest
		err = json.NewDecoder(strings.NewReader(body)).Decode(&req)
		assert.NilError(t, err, "invalid json")
		sig, err := sigparser.ParseSignature(req.EventSignature)
		assert.NilError(t, err, "invalid signature")
		expected := shs.EventTriggerDefinition{
			Contract: common.HexToAddress("0x4d6dd1382aa09be1d243f8960409a1ab3d913f43"),
			LogPredicates: []shs.LogPredicate{
				usecase.Topic0(sig),
				{
					LogValueRef: shs.LogValueRef{
						Offset: 2,
						Length: 1,
					},
					ValuePredicate: shs.ValuePredicate{
						Op:       shs.BytesEq,
						ByteArgs: [][]byte{usecase.Align(toAsBytes)},
					},
				},
			},
		}

		assertTriggerDefinitionEquals(t, body, expected)

		t.Run("complex event data padding required", func(t *testing.T) {
			body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Someevent(address indexed from, address indexed to, uint256 value, byte complex, uint256 second)","arguments": [{"name": "to", "op": "eq", "bytes":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"}, {"name": "complex", "op": "eq", "bytes": "0x746869732069732061206c6f6e6720737472696e672077697468206c6f7473206f6620627974657320616e6420736f20746869732073686f756c64206e6f742066697420696e746f20612073696e676c6520776f7264"}, {"name": "second", "op": "gt", "number": "1"}]}`
			toAsBytes, err := hexutil.Decode("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
			assert.NilError(t, err, "hex decode failed")
			complexArg := common.FromHex("0x746869732069732061206c6f6e6720737472696e672077697468206c6f7473206f6620627974657320616e6420736f20746869732073686f756c64206e6f742066697420696e746f20612073696e676c6520776f7264")
			complexLen := (len(complexArg) + 32) / shs.Word
			var req usecase.EventTriggerDefinitionRequest
			err = json.NewDecoder(strings.NewReader(body)).Decode(&req)
			assert.NilError(t, err, "invalid json")
			sig, err := sigparser.ParseSignature(req.EventSignature)
			assert.NilError(t, err, "invalid signature")
			assert.Equal(t, len(usecase.Align(complexArg)), 96)
			assert.Equal(t, complexLen, 3)
			expected := shs.EventTriggerDefinition{
				Contract: common.HexToAddress("0x4d6dd1382aa09be1d243f8960409a1ab3d913f43"),
				LogPredicates: []shs.LogPredicate{
					usecase.Topic0(sig),
					{
						LogValueRef: shs.LogValueRef{
							Offset: 2,
							Length: 1,
						},
						ValuePredicate: shs.ValuePredicate{
							Op:       shs.BytesEq,
							ByteArgs: [][]byte{usecase.Align(toAsBytes)},
						},
					},
					{
						LogValueRef: shs.LogValueRef{
							Offset: 4,
							Length: uint64(complexLen),
						},
						ValuePredicate: shs.ValuePredicate{
							Op:       shs.BytesEq,
							ByteArgs: [][]byte{usecase.Align(complexArg)},
						},
					},
					{
						LogValueRef: shs.LogValueRef{
							Offset: 4 + uint64(complexLen),
							Length: 1,
						},
						ValuePredicate: shs.ValuePredicate{
							Op:      shs.UintGt,
							IntArgs: []*big.Int{big.NewInt(1)},
						},
					},
				},
			}
			assert.NilError(t, expected.Validate(), "did not validate")

			assertTriggerDefinitionEquals(t, body, expected)
		})
	})
}
