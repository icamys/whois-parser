package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserCl(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.cl", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "https://markmonitor.com/", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2002-10-22 17:48:23 CLST", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-11-20 14:48:02 CLST", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
			{TargetField: "WhoisServer", ExpectedResult: "whois.nic.cl", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_cl/google.cl.txt"
	parserName := ".cl parser"

	runParserAssertions(t, clParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserClNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_cl/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = clParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserClMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_cl/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = clParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
