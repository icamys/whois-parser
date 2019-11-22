package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserTh(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "GOOGLE.CO.TH", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "T.H.NIC Co., Ltd.", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS3.GOOGLE.COM", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "ACTIVE", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "16 Sep 2019", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "08 Oct 2004", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "07 Oct 2020", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "Personal Information*", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "US", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "Organization", ExpectedResult: "Personal Information*", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "Personal Information*", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_th/google.co.th.txt"
	parserName := ".th parser"

	runParserAssertions(t, thParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserThNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_th/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = thParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
