package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserSu(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "GOOGLE.SU", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns3.nic.ru.", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "REGISTERED, DELEGATED", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "domens@mail.com", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "RUCENTER-SU", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2005-10-15T20:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-10-15T21:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-11-22T14:46:31Z", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Private Person", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_su/google.su.txt"
	parserName := ".su parser"

	runParserAssertions(t, suParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserSuNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_su/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = suParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
