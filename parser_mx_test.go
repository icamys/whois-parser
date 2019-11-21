package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserMx(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.mx", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-05-11", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-04-12", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "http://www.markmonitor.com/", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns2.google.com", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "California", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "United States", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "California", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "United States", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "California", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "United States", AssertType: AssertTypeEqual},
		},

		"Bill": {
			{TargetField: "Name", ExpectedResult: "MarkMonitor", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Boise", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "Idaho", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "United States", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_mx/google.mx.txt"
	parserName := ".mx parser"

	runParserAssertions(t, mxParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserMxNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_mx/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = mxParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserMxMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_mx/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = mxParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
