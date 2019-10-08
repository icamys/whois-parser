package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserTr(t *testing.T) {
	assertParamsMap := AssertParamsMap{
		"Registrar": {
			{TargetField: "DomainName", ExpectedResult: "arneca.com.tr", AssertType: AssertTypeEqual},
			{TargetField: "CreatedDate", ExpectedResult: "2018-May-25", AssertType: AssertTypeEqual},
			{TargetField: "ExpirationDate", ExpectedResult: "2023-May-24", AssertType: AssertTypeEqual},
			{TargetField: "RegistrarName", ExpectedResult: "Çizgi Telekomünikasyon A.Ş.", AssertType: AssertTypeEqual},
		},
		"Registrant": {
			{TargetField: "Name", ExpectedResult: "Arneca Danışmanlık ve Ticaret LTD. ŞTİ.", AssertType: AssertTypeEqual},
			{TargetField: "Street", ExpectedResult: "İTÜ Ayazağa Kampüsü ARI2 Teknokent A Blok 4-5", AssertType: AssertTypeEqual},
			{TargetField: "City", ExpectedResult: "İstanbul", AssertType: AssertTypeEqual},
			{TargetField: "Email", ExpectedResult: "ahmet.akkok@outlook.com", AssertType: AssertTypeEqual},
			{TargetField: "Phone", ExpectedResult: "+ 90-212-2861266-", AssertType: AssertTypeEqual},
			{TargetField: "Country", ExpectedResult: "Türkiye", AssertType: AssertTypeEqual},
			{TargetField: "PostalCode", ExpectedResult: "34349", AssertType: AssertTypeEqual},
		},
		"Admin": {
			{TargetField: "City", ExpectedResult: "İstanbul", AssertType: AssertTypeEqual},
		},
		"Tech": {
			{TargetField: "Name", ExpectedResult: "Ahmet Akkök", AssertType: AssertTypeEqual},
		},
	}

	testDataFilepath := "test_data/whois_tr/arneca.com.tr.txt"
	parserName := ".tr parser"

	testParser(t, trParser, assertParamsMap, testDataFilepath, parserName)
}

func TestParserTrNoSuchDomainErr(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_tr/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = trParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}

func TestParserTrMalformedRequest(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_tr/no_such_domain.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = trParser.Parse(text)

	assert.True(t, whoisRecord.ErrCode == ErrCodeNoSuchDomain)
	assert.Nil(t, whoisRecord.Registrar)
	assert.Nil(t, whoisRecord.Registrant)
	assert.Nil(t, whoisRecord.Bill)
	assert.Nil(t, whoisRecord.Admin)
	assert.Nil(t, whoisRecord.Tech)
}
