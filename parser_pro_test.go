package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserPro(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "GOOGLE.PRO", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D107300000000011545-LRMS", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "whois.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "http://www.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-08-07T09:30:57Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2008-07-22T00:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-09-08T00:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: "292", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited", AssertType: AssertTypeContains},
			{TargetField: "NameServers", ExpectedResult: "NS1.GOOGLE.COM", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_pro/google.pro.txt"
	parserName := ".pro parser"

	runParserAssertions(t, proParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserProNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_pro/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = proParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserProMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_pro/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = proParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
