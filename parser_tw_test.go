package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserTw(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "CreatedDate", ExpectedResult: "07-Apr-1998", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Domain Admin", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_tw/google.tw.txt"
	parserName := ".tw parser"

	runParserAssertions(t, twParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserTwNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_tw/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = twParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserTwMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_tw/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = twParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
