package service

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defiweb/go-sigparser"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	shs "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice"
	help "github.com/shutter-network/rolling-shutter/rolling-shutter/keyperimpl/shutterservice/help"
	shcommon "github.com/shutter-network/shutter-api/common"
	"github.com/shutter-network/shutter-api/internal/usecase"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
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

	t.Run(
		"indexed from + amount",
		func(t *testing.T) {
			body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Transfer(address indexed from, address indexed to, uint256 amount)","arguments": [{"name": "from", "op": "eq", "bytes": "0x9e13976721ebff885611c8391d9b02749c1283fa"},{"name": "amount", "op": "gte", "number": "1"}]}`
			fromAsBytes := common.HexToAddress("0x9e13976721ebff885611c8391d9b02749c1283fa").Bytes()
			var req usecase.EventTriggerDefinitionRequest
			err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
			assert.NilError(t, err, "invalid json")
			sig, err := sigparser.ParseSignature(req.EventSignature)
			expected := shs.EventTriggerDefinition{
				Contract: common.HexToAddress("0x4D6dD1382AA09be1d243F8960409A1ab3d913F43"),
				LogPredicates: []shs.LogPredicate{
					usecase.Topic0(sig),
					{
						LogValueRef: shs.LogValueRef{Offset: 1},
						ValuePredicate: shs.ValuePredicate{
							Op:       shs.BytesEq,
							ByteArgs: [][]byte{usecase.Align(fromAsBytes)},
						},
					},
					{
						LogValueRef: shs.LogValueRef{Offset: 4},
						ValuePredicate: shs.ValuePredicate{
							Op:      shs.UintGte,
							IntArgs: []*big.Int{big.NewInt(1)},
						},
					},
				},
			}

			assertTriggerDefinitionEquals(t, body, expected)
		},
	)

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
					LogValueRef: shs.LogValueRef{Offset: 2},
					ValuePredicate: shs.ValuePredicate{
						Op:       shs.BytesEq,
						ByteArgs: [][]byte{usecase.Align(toAsBytes)},
					},
				},
			},
		}

		assertTriggerDefinitionEquals(t, body, expected)
	})
	t.Run("complex event data padding required", func(t *testing.T) {
		body := `{"contract": "0x4d6dd1382aa09be1d243f8960409a1ab3d913f43", "eventSig":"event Someevent(address indexed from, address indexed to, uint256 value, byte complex, uint256 second)","arguments": [{"name": "to", "op": "eq", "bytes":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"}, {"name": "complex", "op": "eq", "bytes": "0x746869732069732061206c6f6e6720737472696e672077697468206c6f7473206f6620627974657320616e6420736f20746869732073686f756c64206e6f742066697420696e746f20612073696e676c6520776f7264"}, {"name": "second", "op": "gt", "number": "1"}]}`
		toAsBytes, err := hexutil.Decode("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
		assert.NilError(t, err, "hex decode failed")
		complexArg := common.FromHex("0x746869732069732061206c6f6e6720737472696e672077697468206c6f7473206f6620627974657320616e6420736f20746869732073686f756c64206e6f742066697420696e746f20612073696e676c6520776f7264")
		var req usecase.EventTriggerDefinitionRequest
		err = json.NewDecoder(strings.NewReader(body)).Decode(&req)
		assert.NilError(t, err, "invalid json")
		sig, err := sigparser.ParseSignature(req.EventSignature)
		assert.NilError(t, err, "invalid signature")
		assert.Equal(t, len(usecase.Align(complexArg)), 96)
		expected := shs.EventTriggerDefinition{
			Contract: common.HexToAddress("0x4d6dd1382aa09be1d243f8960409a1ab3d913f43"),
			LogPredicates: []shs.LogPredicate{
				usecase.Topic0(sig),
				{
					LogValueRef: shs.LogValueRef{Offset: 2},
					ValuePredicate: shs.ValuePredicate{
						Op:       shs.BytesEq,
						ByteArgs: [][]byte{usecase.Align(toAsBytes)},
					},
				},
				{
					LogValueRef: shs.LogValueRef{Offset: 5},
					ValuePredicate: shs.ValuePredicate{
						Op:       shs.BytesEq,
						ByteArgs: [][]byte{complexArg},
					},
				},
				{
					LogValueRef: shs.LogValueRef{Offset: 6},
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
}

func createETD(t *testing.T, setup help.Setup, signature string, args []string) shs.EventTriggerDefinition {
	t.Helper()

	b := strings.Builder{}
	b.WriteString("[")
	for i, arg := range args {
		b.WriteString(arg)
		if i < len(args)-1 {
			b.WriteString(",")
		}
	}
	b.WriteString("]")
	argumentsJson := b.String()

	jsonString := fmt.Sprintf(
		`{"contract": "%v", "eventSig": "%v", "arguments": %v}`,
		setup.ContractAddress.Hex(),
		signature,
		argumentsJson,
	)
	var record usecase.EventTriggerDefinitionRequest
	err := json.Unmarshal([]byte(jsonString), &record)

	assert.NilError(t, err, "json creation failed")

	response, errors := usecase.CompileEventTriggerDefinitionInternal(record)
	assert.Check(t, len(errors) == 0, "errors during compilation: %v", errors)
	etd := shs.EventTriggerDefinition{}
	data, err := hexutil.Decode(response.EventTriggerDefinition)
	assert.NilError(t, err, "could not decode: '%v' err: %v", response.EventTriggerDefinition, err)
	err = etd.UnmarshalBytes(data)
	assert.NilError(t, err, "error unmarshalling: %v", err)
	return etd
}

func TestWithEVM(t *testing.T) {
	signatureString := "event Six(uint256 indexed one, string indexed two, address indexed three, bytes four, uint256 five, bytes six)"
	setup := help.SetupBackend(t)
	one := big.NewInt(1)
	jOne := fmt.Sprintf(`{"name": "one", "op": "eq", "bytes": "%v"}`, hexutil.Encode(one.Bytes()))
	mOne := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 1},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{shs.Align(one.Bytes())}},
	}
	two := "two"
	jTwo := fmt.Sprintf(`{"name": "two", "op": "eq", "bytes": "%v"}`, hexutil.Encode(shs.Align(crypto.Keccak256([]byte("two")))))
	mTwo := shs.LogPredicate{
		LogValueRef: shs.LogValueRef{Offset: 2},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{
			shs.Align(crypto.Keccak256([]byte("two"))),
		}},
	}
	three := common.BytesToAddress(big.NewInt(84).Bytes())
	jThree := fmt.Sprintf(`{"name": "three", "op": "eq", "bytes": "%v"}`, three.Hex())
	mThree := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 3},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{shs.Align(three[:])}},
	}
	four := []byte("first and slightly longer arg that should use more space and if i am right, then this will span multiple words")
	jFour := fmt.Sprintf(`{"name": "four", "op": "eq", "bytes": "%v"}`, hexutil.Encode([]byte(four)))

	mFour := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 4},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{four}},
	}
	jNoMFour := fmt.Sprintf(`{"name": "four", "op": "eq", "bytes": "%v"}`, hexutil.Encode([]byte("no match")))
	noMFour := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 4},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{[]byte("no match")}},
	}
	preFour := []byte("first and slightly longer arg that should use more space and if ")
	jPreNotFour := fmt.Sprintf(`{"name": "four", "op": "eq", "bytes": "%v"}`, hexutil.Encode([]byte(preFour)))
	preNotFour := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 4},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{preFour}},
	}
	five := big.NewInt(42)
	jFive := `{"name": "five", "op": "gte", "number": "42"}`

	six := []byte("second arg")
	jSix := fmt.Sprintf(`{"name": "six", "op": "eq", "bytes": "%v"}`, hexutil.Encode(six))
	mSix := shs.LogPredicate{
		LogValueRef:    shs.LogValueRef{Offset: 6},
		ValuePredicate: shs.ValuePredicate{Op: shs.BytesEq, ByteArgs: [][]byte{six}},
	}

	tx, err := setup.Contract.EmitSix(setup.Auth, one, two, three, four, five, six)
	assert.NilError(t, err, "error creating tx")
	vLog, err := help.CollectLog(t, setup, tx)
	assert.NilError(t, err, "error getting log")

	sig, err := sigparser.ParseSignature(signatureString)
	assert.NilError(t, err, "error parsing signature")
	t0 := usecase.Topic0(sig)

	tests := []struct {
		args       []string
		predicates []shs.LogPredicate
		match      bool
		name       string
	}{
		{
			args:       []string{jOne, jTwo, jThree, jSix},
			predicates: []shs.LogPredicate{t0, mOne, mTwo, mThree, mSix},
			match:      true,
			name:       "match one, two, three and six",
		},
		{args: []string{jFour}, predicates: []shs.LogPredicate{t0, mFour}, match: true, name: "match four"},
		{args: []string{jFour, jSix}, predicates: []shs.LogPredicate{t0, mFour, mSix}, match: true, name: "match four and six"},
		{args: []string{jPreNotFour}, predicates: []shs.LogPredicate{t0, preNotFour}, match: false, name: "prefix should not match whole"},
		{args: []string{jNoMFour}, predicates: []shs.LogPredicate{t0, noMFour}, match: false, name: "mismatch four"},
		{
			args: []string{jFive},
			predicates: []shs.LogPredicate{
				t0,
				{
					LogValueRef: shs.LogValueRef{Offset: 5},
					ValuePredicate: shs.ValuePredicate{
						Op:      shs.UintGte,
						IntArgs: []*big.Int{five},
					},
				},
			},
			match: true,
			name:  "match five GTE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jEtd := createETD(t, setup, signatureString, tt.args)
			etd := shs.EventTriggerDefinition{
				Contract:      setup.ContractAddress,
				LogPredicates: tt.predicates,
			}
			valid := jEtd.Validate()
			assert.Check(t, valid, "json did not lead to valid ETD: %v", tt.args)
			equalBytes := cmp.DeepEqual(etd.MarshalBytes(), jEtd.MarshalBytes())
			assert.Check(t, equalBytes, "json marshaled bytes not equal to struct; \nJSON:\n%v \nVS OTHER:\n%v", jEtd, etd)
			match, err := jEtd.Match(vLog)
			assert.NilError(t, err, "error when matching from JSON: %v", err)
			assert.Check(t, match == tt.match, "did not match expectation: %v", jEtd)
		})
	}
}
