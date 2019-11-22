package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserKz(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.kz", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.google.com", AssertType: AssertTypeContains},
			{TargetField: "CreatedDate", ExpectedResult: "1999-06-07 13:01:43 (GMT+0:00)", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "ok - Normal state.", AssertType: AssertTypeContains},
			{TargetField: "UpdatedDate", ExpectedResult: "2012-11-28 03:16:59 (GMT+0:00)", AssertType: AssertTypeContains},
			{TargetField: "RegistrarName", ExpectedResult: "KAZNIC", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "2400 E. Bayshore Pkwy", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "94043", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "ID", ExpectedResult: "C000000197393-KZ", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "DNS Admin", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+1.6502530000 ", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "+1.6506188571 ", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "ccops@markmonitor.com", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_kz/google.kz.txt"
	parserName := ".kz parser"

	runParserAssertions(t, kzParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserKzNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_kz/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = kzParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
