package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserUk(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "run.uk", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "Lexsynergy Ltd [Tag = LEXSYNERGY]", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "26-Nov-2014", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "26-Nov-2019", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "26-Jul-2019", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "Registered until expiry date.", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns2.uniregistrymarket.link", AssertType: AssertTypeContains},
		},
	}

	testDataFilepath := "test_data/whois_uk/run.uk.txt"
	parserName := ".uk parser"

	runParserAssertions(t, ukParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserUkNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_uk/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ukParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserUkMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_uk/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ukParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserUkRateLimit(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_uk/rate_limit.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ukParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeRequestRateLimit)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
