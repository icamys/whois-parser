package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"regexp"
	"testing"
)

func TestFindAndJoinStrings(t *testing.T) {
	var text string
	var re *regexp.Regexp

	text = "asd asf Asd"
	re = regexp.MustCompile(`(?i)(asd)`)
	res, found := findAndJoinStrings(&text, re)

	assert.True(t, found)
	assert.True(t, "asd,Asd" == res || "Asd,asd" == res)
}

func TestParseGeographicalAddress(t *testing.T) {
	var text string
	var re *regexp.Regexp
	var registrant Registrant
	text = "Address: Troya, Rim, JustAStreet"
	re = regexp.MustCompile(`Address:(?: (?P<country>.*?), (?P<city>.*?), (?P<street>.*?))$`)
	registrant = Registrant{}
	parseGeographicalAddress(&registrant, re, &text)
	assert.Equal(t, "Troya", registrant.Country)
	assert.Equal(t, "Rim", registrant.City)
	assert.Equal(t, "JustAStreet", registrant.Street)
}

func TestDefaultParser(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisInfo *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_com/google.com.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisInfo = DefaultParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.Contains(t, whoisInfo.Registrar.DomainName, "GOOGLE.COM")
	assert.Contains(t, whoisInfo.Registrar.DomainName, "google.com")
	assert.Equal(t, whoisInfo.Registrant.Country, "US")
	assert.Equal(t, whoisInfo.Registrant.Province, "CA")
	assert.Equal(t, whoisInfo.Registrant.Organization, "Google LLC")

	assert.Equal(t, "unsigned", whoisInfo.Registrar.DomainDNSSEC)
	assert.Len(t, whoisInfo.Registrar.DomainStatus, 141)

	statuses := []string{
		"serverUpdateProhibited",
		"clientDeleteProhibited",
		"clientTransferProhibited",
		"clientUpdateProhibited",
		"serverDeleteProhibited",
		"serverTransferProhibited",
	}

	for _, s := range statuses {
		assert.Contains(t, whoisInfo.Registrar.DomainStatus, s)
	}

	assert.Equal(t, "abusecomplaints@markmonitor.com", whoisInfo.Registrar.Emails)
}

func TestDefaultParserNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_com/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data") //TODO Duplicate NoError assert?

	text = string(fileBytes)

	whoisRecord = DefaultParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data") //TODO Duplicate NoError assert?

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestDefaultParserMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_com/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = DefaultParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.Equal(t, ErrCodeMalformedRequest, whoisRecord.ErrCode)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
