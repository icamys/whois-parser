package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserPl(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "top.pl", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "Unsigned", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2019.12.20 09:08:33", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2018.11.20 16:09:18", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "1997.04.14 13:00:00", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_pl/top.pl.txt"
	parserName := ".pl parser"

	runParserAssertions(t, plParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserPlNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_pl/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = plParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserPlMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_pl/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = plParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserPlRateLimit(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_pl/rate_limit.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = plParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeRequestRateLimit)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
