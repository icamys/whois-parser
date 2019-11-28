package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserEdu(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "CreatedDate", ExpectedResult: "07-Apr-1998", AssertType: AssertTypeEqual},
			{TargetField: "DomainName", ExpectedResult: "USG.EDU", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "31-Jul-2020", AssertType: AssertTypeEqual},
			{TargetField: "UpdatedDate", ExpectedResult: "26-Sep-2019", AssertType: AssertTypeEqual},
			{TargetField: "WhoisServer", ExpectedResult: "http://whois.educause.edu", AssertType: AssertTypeEqual},
			{TargetField: "Emails", ExpectedResult: "nic-admin@usg.edu", AssertType: AssertTypeEqual},
			{TargetField: "NameServers", ExpectedResult: "NS3.USG.EDU", AssertType: AssertTypeContains},
		},

		"Registrant": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
		},

		"Admin": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "Domain Admin", AssertType: AssertTypeEqual},
		},

		"Tech": {
			{TargetField: "Organization", ExpectedResult: "Board of Regents of the University System of Georgia", AssertType: AssertTypeEqual},
			{TargetField: "Name", ExpectedResult: "", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_edu/usg.edu.txt"
	parserName := ".edu parser"

	runParserAssertions(t, eduParser, parserName, testDataFilepath, assertParamsMap)
}

func TestParserEduNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_edu/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = eduParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserEduMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_edu/malformed_request.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = eduParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.True(t, whoisRecord.ErrCode == ErrCodeMalformedRequest)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
