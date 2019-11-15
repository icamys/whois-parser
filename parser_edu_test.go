package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserRu(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "GG.RU", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2001-12-03T21:00:00Z", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "REGISTERED, DELEGATED, VERIFIED", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-01-05", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.privateperson.ru", AssertType: AssertTypeContains},
			{TargetField: "NameServers", ExpectedResult: "ns2.privateperson.ru", AssertType: AssertTypeContains},
			{TargetField: "RegistrarName", ExpectedResult: "SALENAMES-RU", AssertType: AssertTypeEqual},
		},
		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Private Person", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_ru/gg.ru.txt"
	parserName := ".ru parser"

	runParserAssertions(t, ruParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserRuRateLimit(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ru/rate_limit.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ruParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeRequestRateLimit)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserRuNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ru/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ruParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
