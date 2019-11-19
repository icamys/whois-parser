package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserId(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainID", ExpectedResult: "PANDI-DO522803", AssertType: AssertTypeEqual},
			{TargetField: "DomainName", ExpectedResult: "HUMANITARIAN.ID", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "16-Oct-2014 09:43:07 UTC", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "30-Nov-2018 05:57:03 UTC", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "16-Oct-2024 23:59:59 UTC", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "ok", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS1-03.AZURE-DNS.COM", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "Unsigned", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "PT INDOSAT MEGA MEDIA", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "ID", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "DKI Jakarta", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Jakarta Selatan", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "12550", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "02178546969", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "02178546999", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "optech@indosat.net.id", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_id/humanitarian.id.txt"
	parserName := ".id parser"

	runParserAssertions(t, idParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserIdNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_id/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = idParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
