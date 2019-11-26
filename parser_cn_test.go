package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserCn(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.cn", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "20030311s10001s00033735-cn", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientDeleteProhibited", AssertType: AssertTypeContains},
			{TargetField: "NameServers", ExpectedResult: "ns2.google.com", AssertType: AssertTypeContains},
			{TargetField: "CreatedDate", ExpectedResult: "2003-03-17 12:20:05", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2021-03-17 12:48:36", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "ID", ExpectedResult: "ename_el7lxxxazw", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "北京谷翔信息技术有限公司", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "dns-admin@google.com", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_cn/google.cn.txt"
	parserName := ".cn parser"

	runParserAssertions(t, cnParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserCnNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_cn/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = cnParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserCnMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_cn/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = cnParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
