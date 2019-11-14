package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserIr(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "run.ir", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2021-04-19", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS6.ICH-4.COM", AssertType: AssertTypeContains},
			{TargetField: "UpdatedDate", ExpectedResult: "2018-06-17", AssertType: AssertTypeEqual},
		},
		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Behzad Eghtesad", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Tehran", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "Tehran", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "IR", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "Aazadi Ave.,", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_ir/run.ir.txt"
	parserName := ".ir parser"

	runParserAssertions(t, irParser, parserName, testDataFilepath, assertParamsMap)
}
func TestParserIrMalformedRequestErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ir/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = irParser.Parse(text)

	assert.Equal(t, ErrCodeMalformedRequest, whoisRecord.ErrCode)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserIrMalformedRequestErrIsEqualToNoSuchDomainErr(t *testing.T) {
	assert.Equal(t, irParser.errorRegex.NoSuchDomain.String(), irParser.errorRegex.MalformedRequest.String())
}
