package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserFr(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.fr", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "ACTIVE", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MARKMONITOR Inc.", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2019-12-30T17:16:48Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2000-07-26T22:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2018-11-28T10:31:42Z", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
		},
	}

	testDataFilepath := "test_data/whois_fr/google.fr.txt"
	parserName := ".fr parser"

	runParserAssertions(t, frParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserFrNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_fr/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = frParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
