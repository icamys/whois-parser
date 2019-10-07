package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserUa(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "viyar.ua", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns10.uadns.com", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "ok", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2013-08-09 13:13:06+03", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-07-10 12:54:59+03", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-08-09 13:13:06+03", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "abuse@nic.ua", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "ua.nic", AssertType: AssertTypeEqual},
		},
		"Tech": {
			{TargetField: "Name", ExpectedResult: "NIC.UA LLC", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "ТОВ \"НІК.ЮЕЙ\"", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "Plehanova", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "support@nic.ua", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_ua/viyar.ua.txt"
	parserName := ".ua parser"

	testParser(t, uaParser, assertParamsMap, testDataFilepath, parserName)
}

func TestParserUaNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ua/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = uaParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserUaMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_ua/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = uaParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.Equal(t, ErrCodeMalformedRequest, whoisRecord.ErrCode)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
