package whoisparser

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"reflect"
	"regexp"
	"testing"
)

type AssertParams struct {
	TargetField    string
	ExpectedResult interface{}
	AssertType     int
}

type AssertParamsMap map[string][]*AssertParams

const (
	AssertTypeContains = iota
	AssertTypeEqual
	AssertTypeLen
)

func runParserAssertions(
	t *testing.T,
	parser *Parser,
	parserName string,
	testDataFilePath string,
	assertParamsMap AssertParamsMap,
) {
	var fileBytes []byte
	var err error
	var text string
	var whoisRecord *Record
	var whoisRecordReflect reflect.Value
	var assertMsg string
	var assertMsgFormat = "failed on parser \"%s\"\nstructure \"%s.%s\"\npath to input file: \"%s\""

	fileBytes, err = ioutil.ReadFile(testDataFilePath)
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisRecord = parser.Parse(text)
	whoisRecordReflect = reflect.ValueOf(whoisRecord).Elem()
	for fieldName, assertParamsList := range assertParamsMap {
		for _, assertParams := range assertParamsList {
			actualField := whoisRecordReflect.
				FieldByName(fieldName).Elem().
				FieldByName(assertParams.TargetField).Interface()
			assertMsg = fmt.Sprintf(assertMsgFormat, parserName, fieldName, assertParams.TargetField, testDataFilePath)
			switch assertParams.AssertType {
			case AssertTypeContains:
				assert.Contains(t, actualField, assertParams.ExpectedResult, assertMsg)
			case AssertTypeEqual:
				assert.Equal(t, assertParams.ExpectedResult, actualField, assertMsg)
			case AssertTypeLen:
				assert.Len(t, actualField, assertParams.ExpectedResult.(int), assertMsg)
			}
		}
	}
}

func TestFindAndJoinStrings(t *testing.T) {
	var text string
	var re *regexp.Regexp

	text = "asd asf Asd"
	re = regexp.MustCompile(`(?i)(asd)`)
	res, found := findAndJoinStrings(&text, re)

	assert.True(t, found)
	assert.True(t, "asd,Asd" == res || "Asd,asd" == res)
}

func TestFillGeoAddress(t *testing.T) {
	var text string
	var re *regexp.Regexp
	var registrant Registrant
	text = "Address: Troya, Menzoberranzan, JustAStreet, Empty"
	re = regexp.MustCompile(`Address:(?: (?P<country>.*?), (?P<city>.*?), (?P<street>.*?), (?P<province>.*?))$`)
	registrant = Registrant{}
	skipWordList := []string{"Empty"}
	fillGeoAddress(&registrant, re, &text, skipWordList)
	assert.Equal(t, "Troya", registrant.Country)
	assert.Equal(t, "Menzoberranzan", registrant.City)
	assert.Equal(t, "JustAStreet", registrant.Street)
	assert.Equal(t, "", registrant.Province)
}

func TestParserForRegisterParserOrderByZoneLengthAsc(t *testing.T) {
	var (
		tldPlus2Parser = &DefaultParser
		tldPlus1Parser = coJpParser
		tldParser      = jpParser
	)

	RegisterParser(".ex.co.jp", tldPlus2Parser)
	RegisterParser(".co.jp", tldPlus1Parser)
	RegisterParser(".jp", tldParser)

	assert.Equal(t, parserFor("example.ex.co.jp"), tldPlus2Parser)
	assert.Equal(t, parserFor("example.co.jp"), tldPlus1Parser)
	assert.Equal(t, parserFor("example.jp"), tldParser)

	assert.NotEqual(t, parserFor("example.co.jp"), tldPlus2Parser)
	assert.NotEqual(t, parserFor("example.jp"), tldPlus2Parser)

	assert.NotEqual(t, parserFor("example.ex.co.jp"), tldPlus1Parser)
	assert.NotEqual(t, parserFor("example.jp"), tldPlus1Parser)

	assert.NotEqual(t, parserFor("example.ex.co.jp"), tldParser)
	assert.NotEqual(t, parserFor("example.co.jp"), tldParser)
}

func TestParserForRegisterParserOrderByZoneLengthDesc(t *testing.T) {
	var (
		tldPlus2Parser = &DefaultParser
		tldPlus1Parser = coJpParser
		tldParser      = jpParser
	)

	RegisterParser(".jp", tldParser)
	RegisterParser(".co.jp", tldPlus1Parser)
	RegisterParser(".ex.co.jp", tldPlus2Parser)

	assert.Equal(t, parserFor("example.ex.co.jp"), tldPlus2Parser)
	assert.Equal(t, parserFor("example.co.jp"), tldPlus1Parser)
	assert.Equal(t, parserFor("example.jp"), tldParser)

	assert.NotEqual(t, parserFor("example.co.jp"), tldPlus2Parser)
	assert.NotEqual(t, parserFor("example.jp"), tldPlus2Parser)

	assert.NotEqual(t, parserFor("example.ex.co.jp"), tldPlus1Parser)
	assert.NotEqual(t, parserFor("example.jp"), tldPlus1Parser)

	assert.NotEqual(t, parserFor("example.ex.co.jp"), tldParser)
	assert.NotEqual(t, parserFor("example.co.jp"), tldParser)
}

func TestParseRegistrantNilAddressRegex(t *testing.T) {
	var text string
	text = `Registrant Country: UK
			Registrant Province: Empty`
	registrantRegex := RegistrantRegex{
		Country:  regexp.MustCompile(`(?i)Registrant Country: *(.+)`),
		Province: regexp.MustCompile(`(?i)Registrant Province: *(.+)`),
	}
	skipWordList := []string{"Empty"}
	registrant := parseRegistrant(&text, &registrantRegex, skipWordList)
	assert.Equal(t, "UK", registrant.Country)
	assert.Equal(t, "", registrant.Province)
}

func TestParseRegistrantNotNilAddressRegex(t *testing.T) {
	var text string
	text = "Address: Troya, Menzoberranzan, JustAStreet"
	registrantRegex := RegistrantRegex{
		Address: regexp.MustCompile(`Address:(?: (?P<country>.*?), (?P<city>.*?), (?P<street>.*?))$`),
		Country: regexp.MustCompile(`(?i)Registrant Country: *(.+)`),
	}
	skipWordList := []string{""}
	registrant := parseRegistrant(&text, &registrantRegex, skipWordList)
	assert.Equal(t, "Troya", registrant.Country)
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
	assert.Contains(t, whoisInfo.Registrar.RegistrarName, "MarkMonitor, Inc.")
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

func TestDefaultParserDoesNotCaptureEmptyGroups(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisInfo *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_com/run.com.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisInfo = DefaultParser.Parse(text)
	assert.Equal(t, whoisInfo.Registrant.Fax, "")
	assert.Equal(t, whoisInfo.Registrant.ID, "")
	assert.Equal(t, whoisInfo.Admin.Fax, "")

}
