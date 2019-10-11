package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserJp(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "TEST.JP", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2018/06/08", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "Active", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns-783.awsdns-33.net", AssertType: AssertTypeContains},
			{TargetField: "Emails", ExpectedResult: "nic-staff@sakura.ad.jp", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_jp/test.jp.txt"
	parserName := ".jp parser"

	testParser(t, jpParser, assertParamsMap, testDataFilepath, parserName)
}

func TestParserJpNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_jp/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = jpParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserJpMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_jp/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = jpParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserJpRateLimit(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_jp/rate_limit.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = jpParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeRequestRateLimit)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
