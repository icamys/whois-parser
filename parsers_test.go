package whoisparser

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"reflect"
	"testing"
)

type AssertParams struct {
	TargetField    string
	ExpectedResult interface{}
	AssertType     int
}

type AssertParamsMap map[string][]*AssertParams

const (
	AssertTypeContains = iota
	AssertTypeEqual
	AssertTypeLen
)

func TestParserOrg(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "WIKIPEDIA.ORG", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "whois.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS2.WIKIMEDIA.ORG", AssertType: AssertTypeContains},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: 3, AssertType: AssertTypeLen},
		},
		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Wikimedia Foundation, Inc.", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_org/wikipedia.org.txt"
	parserName := ".org parser"

	testParser(t, orgParser, assertParamsMap, testDataFilepath, parserName)
}

func testParser(t *testing.T, parser *Parser, assertParamsMap AssertParamsMap, inputFilepath, parserName string) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record
	var whoisRecordReflect reflect.Value
	var assertMsg string
	var assertMsgFormat = "failed on \"%s\"\nstructure \"%s.%s\"\npath to input file: \"%s\""

	fileBytes, err = ioutil.ReadFile(inputFilepath)
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = parser.Parse(text)
	whoisRecordReflect = reflect.ValueOf(whoisRecord).Elem()
	for fieldName, assertParamsList := range assertParamsMap {
		for _, assertParams := range assertParamsList {
			actualField := whoisRecordReflect.
				FieldByName(fieldName).Elem().
				FieldByName(assertParams.TargetField).Interface()
			assertMsg = fmt.Sprintf(assertMsgFormat, parserName, fieldName, assertParams.TargetField, inputFilepath)
			switch assertParams.AssertType {
			case AssertTypeContains:
				assert.Contains(t, actualField, assertParams.ExpectedResult, assertMsg)
			case AssertTypeEqual:
				assert.Equal(t, assertParams.ExpectedResult, actualField, assertMsg)
			case AssertTypeLen:
				assert.Len(t, actualField, assertParams.ExpectedResult.(int), assertMsg)
			}
		}
	}
}
