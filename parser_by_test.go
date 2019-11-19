package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserBy(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.by", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "Open Contact, Ltd", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-01-10", AssertType: AssertTypeContains},
			{TargetField: "CreatedDate", ExpectedResult: "2004-05-14", AssertType: AssertTypeContains},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-02-09", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Google LLC", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "HIDDEN! Details are available at http://www.cctld.by/whois/", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+1.2083895740", AssertType: AssertTypeEqual},
			{TargetField: "ID", ExpectedResult: "-", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_by/google.by.txt"
	parserName := ".by parser"

	runParserAssertions(t, byParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserByNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_by/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = byParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserByMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_by/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = byParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
