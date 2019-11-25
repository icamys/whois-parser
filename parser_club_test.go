package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserClub(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "jovi.club", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D8751672-CLUB", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "www.nic.ru", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-11-18T09:40:26Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2016-12-29T07:58:21Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-12-28T23:59:59Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "Regional Network Information Center, JSC dba RU-CENTER", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: "463", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "Tld-abuse@nic.ru", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns2.hc.ru", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientTransferProhibited https://icann.org/epp#clientTransferProhibited", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Privacy protection service - whoisproxy.ru", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "Moscow", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "RU", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_club/jovi.club.txt"
	parserName := ".club parser"

	runParserAssertions(t, clubParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserClubNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_club/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = clubParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
