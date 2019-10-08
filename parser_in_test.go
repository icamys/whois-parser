package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserIn(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "studycafe.in", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2011-06-17T09:01:36Z", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D5111534-IN", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited", AssertType: AssertTypeContains},
			{TargetField: "DomainStatus", ExpectedResult: "clientUpdateProhibited http://www.icann.org/epp#clientUpdateProhibited", AssertType: AssertTypeContains},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-04-11T11:29:48Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2021-06-17T09:01:36Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "GoDaddy.com, LLC", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: "146", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "tom.ns.cloudflare.com", AssertType: AssertTypeContains},
		},
	}

	testDataFilepath := "test_data/whois_in/studicafe.in.txt"
	parserName := ".in parser"

	testParser(t, inParser, assertParamsMap, testDataFilepath, parserName)
}
func TestParserInMalformedRequestErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_in/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = inParser.Parse(text)

	assert.Equal(t, ErrCodeMalformedRequest, whoisRecord.ErrCode)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserInMalformedRequestErrIsEqualToNoSuchDomainErr(t *testing.T) {
	assert.Equal(t, inParser.errorRegex.NoSuchDomain.String(), inParser.errorRegex.MalformedRequest.String())
}
