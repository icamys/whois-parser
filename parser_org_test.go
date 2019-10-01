package whoisparser

// TODO Rename file when more then 1 tld test added!
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
	AssertContains = iota //TODO CONTAINS can be unreliable, because return true when looking string in string
	AssertEqual
	AssertLen
)

func TestParserOrg(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "WIKIPEDIA.ORG", AssertType: AssertEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", AssertType: AssertEqual},
			{TargetField: "WhoisServer", ExpectedResult: "whois.markmonitor.com", AssertType: AssertEqual},
			{TargetField: "NameServers", ExpectedResult: "NS2.WIKIMEDIA.ORG", AssertType: AssertContains},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertEqual},
			{TargetField: "RegistrarID", ExpectedResult: 3, AssertType: AssertLen},
		},
		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Wikimedia Foundation, Inc.", AssertType: AssertEqual},
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
			case AssertContains:
				assert.Contains(t, actualField, assertParams.ExpectedResult, assertMsg)
			case AssertEqual:
				assert.Equal(t, assertParams.ExpectedResult, actualField, assertMsg)
			case AssertLen:
				assert.Len(t, actualField, assertParams.ExpectedResult.(int), assertMsg)
			}
		}
	}
}
