package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserBiz(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.biz", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D2835288-BIZ", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "www.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-02-27T10:56:14Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2002-03-27T16:03:44Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-03-26T23:59:59Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor, Inc.", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: "292", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited", AssertType: AssertTypeContains},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Google LLC", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_biz/google.biz.txt"
	parserName := ".biz parser"

	runParserAssertions(t, bizParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserBizNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_biz/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = bizParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
