package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserUs(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "google.us", AssertType: AssertTypeEqual},
			{TargetField: "DomainID", ExpectedResult: "D775573-US", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "ReferralURL", ExpectedResult: "www.markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-03-22T09:56:02Z", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2002-04-19T23:16:01Z", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2020-04-18T23:59:59Z", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "MarkMonitor, Inc.", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarID", ExpectedResult: "292", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited", AssertType: AssertTypeContains},
			{TargetField: "NameServers", ExpectedResult: "ns2.google.com", AssertType: AssertTypeContains},
			{TargetField: "DomainDNSSEC", ExpectedResult: "unsigned", AssertType: AssertTypeEqual},
		},

		"Registrant": {
			{TargetField: "ID", ExpectedResult: "C37454483-US", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Google Inc", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "Google LLC", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1600 Amphitheatre Parkway", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "94043", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+1.6502530000", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "+1.6502530001", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "dns-admin@google.com", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "ID", ExpectedResult: "C37613731-US", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Christina Chiou", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1600 Amphitheatre Parkway", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "94043", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+1.6502530000", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "+1.6502530001", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "dns-admin@google.com", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "ID", ExpectedResult: "C37613731-US", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Christina Chiou", AssertType: AssertTypeEqual},
			{TargetField: "Organization", ExpectedResult: "Google Inc.", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1600 Amphitheatre Parkway", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Mountain View", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "CA", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "94043", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "US", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+1.6502530000", AssertType: AssertTypeEqual},
			{TargetField: "PhoneExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Fax", ExpectedResult: "+1.6502530001", AssertType: AssertTypeEqual},
			{TargetField: "FaxExt", ExpectedResult: "", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "dns-admin@google.com", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_us/google.us.txt"
	parserName := ".us parser"

	runParserAssertions(t, usParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserUsNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_us/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = usParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
