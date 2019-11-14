package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserOrg(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "WIKIPEDIA.ORG", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "whois.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS2.WIKIMEDIA.ORG", AssertType: AssertTypeContains},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: 3, AssertType: AssertTypeLen},
		},
		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Wikimedia Foundation, Inc.", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_org/wikipedia.org.txt"
	parserName := ".org parser"

	runParserAssertions(t, orgParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserOrgNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_org/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = orgParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserOrgMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_org/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = orgParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserOrgRateLimit(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_org/rate_limit.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = orgParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeRequestRateLimit)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
