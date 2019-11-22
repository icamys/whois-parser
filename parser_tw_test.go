package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserTw(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.tw", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientUpdateProhibited,clientTransferProhibited,clientDeleteProhibited", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-10-31 (YYYY-MM-DD)", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2005-10-27 (YYYY-MM-DD)", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
			{TargetField: "RegistrarName", ExpectedResult: "Markmonitor, Inc.", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "http://www.markmonitor.com/", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
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
