package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserZa(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.net.za", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "DOM_2WR-NET.ZA", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "https://www.zadomains.net/whois", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "https://za.domains/", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-10-30T07:55:01Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2019-10-30T07:54:15Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-10-30T07:54:15Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "ZA Domains", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "complaints@zadomains.net", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "ok https://icann.org/epp#ok", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "ns1.mydnscloud.com", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "ID", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "Owen Valentine", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "Western Cape", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "ZA", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin or Tech contacts of the domain name.", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "ID", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin or Tech contacts of the domain name.", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "ID", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin or Tech contacts of the domain name.", AssertType: AssertTypeEqual},
		},

		"Bill": {
			{TargetField: "ID", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "REDACTED", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin or Tech contacts of the domain name.", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_za/google.net.za.txt"
	parserName := ".za parser"

	runParserAssertions(t, zaParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserZaNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_za/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = zaParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserZaMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_za/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = zaParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
