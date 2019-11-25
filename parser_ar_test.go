package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserAr(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.ar", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "nicar", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2019-11-01 12:21:37.677445", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-11-01 12:28:38.082736", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-11-01 00:00:00", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.markmonitor.com ()", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "GOOGLE INC.", AssertType: AssertTypeEqual},
			{TargetField: "ID", ExpectedResult: "50037928906", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_ar/google.ar.txt"
	parserName := ".ar parser"

	runParserAssertions(t, arParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserArNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ar/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = arParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
