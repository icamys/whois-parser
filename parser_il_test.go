package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserIl(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "mfa.gov.il", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "dns.gov.il", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "Transfer Allowed", AssertType: AssertTypeContains},
			{TargetField: "RegistrarName", ExpectedResult: "Israel Government", AssertType: AssertTypeContains},
			{TargetField: "Emails", ExpectedResult: "", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Tech Tehila", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "+972 2 6664650", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+972 2 6664666", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "Hostmaster AT tehila.gov.il", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Jerusalem", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "91039", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "Israel", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_il/mfa.gov.il.txt"
	parserName := ".il parser"

	runParserAssertions(t, ilParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserIlNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_il/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = ilParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
