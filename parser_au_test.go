package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserAu(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "AUSTRALIA.GOV.AU", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D407400000000235888-AU", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "serverTransferProhibited", AssertType: AssertTypeContains},
			{TargetField: "Emails", ExpectedResult: "registrar@domainname.gov.au", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS-1416.AWSDNS-49.ORG", AssertType: AssertTypeContains},
			{TargetField: "ReferralURL", ExpectedResult: "https://www.domainname.gov.au/", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "Digital Transformation Agency", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-06-04T07:14:57Z", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "whois.auda.org.au", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Digital Transformation Agency (DTA)", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_au/australia.gov.au.txt"
	parserName := ".au parser"

	runParserAssertions(t, auParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserAuNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_au/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = auParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserAuMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_au/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = auParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
