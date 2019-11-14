package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserIt(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "CreatedDate", ExpectedResult: "1999-09-21 00:00:00", AssertType: AssertTypeEqual},
			{TargetField: "DomainDNSSEC", ExpectedResult: "no", AssertType: AssertTypeEqual},
			{TargetField: "DomainName", ExpectedResult: "run.it", AssertType: AssertTypeEqual},
			{TargetField: "DomainStatus", ExpectedResult: "ok / autoRenewPeriod", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2019-09-21", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "DELTA2-REG", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "2019-09-22 00:40:39", AssertType: AssertTypeEqual},
		},
		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Stuart Toomey", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1 Coolmine Woods", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Dublin", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "15", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "IE", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "IE", AssertType: AssertTypeEqual},
		},
		"Admin": {
			{TargetField: "Organization", ExpectedResult: "Stuart Toomey", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Stuart Toomey", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1 Coolmine Woods", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Dublin", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "15", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "IE", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "IE", AssertType: AssertTypeEqual},
		},
		"Tech": {
			{TargetField: "Organization", ExpectedResult: "Delta2", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Stuart Toomey", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "1 Coolmine Woods, Blanchardstown", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "Dublin", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "15", AssertType: AssertTypeEqual},
			{TargetField: "Province", ExpectedResult: "ZZ", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "IE", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_it/run.it.txt"
	parserName := ".it parser"

	runParserAssertions(t, itParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserItNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_it/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = itParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserItMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_it/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = itParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
