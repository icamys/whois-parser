package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserXnPlai(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "XN--B1AQCLQ9D.XN--P1AI", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns3.nic.ru.", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "REGISTERED, DELEGATED, VERIFIED", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "RUCENTER-RF", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "https://www.nic.ru/whois", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2010-11-11T09:01:55Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-11-11T09:01:55Z", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-11-22T15:26:34Z", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Administracia Volskogo municipalnogo raiona", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_xnplai/xn.xnplai.txt"
	parserName := ".xnPlai parser"

	runParserAssertions(t, xnPlaiParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserXnPlaiNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_xnplai/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = xnPlaiParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserXnPlaiMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_xnplai/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = xnPlaiParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
