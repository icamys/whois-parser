package whoisparser

// TODO Rename file when more then 1 tld test added!
import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"reflect"
	"testing"
)

type DataForTest struct {
	Field          string
	ExpectedResult interface{}
	CheckType      int
}

const (
	CONTAINS = iota //TODO CONTAINS can be unreliable, because return true when looking string in string.........
	EQUAL
	LEN
)

func TestStartParserTesters(t *testing.T) { //TODO RENAME

	checkParams := map[string][]*DataForTest{
		"Registrar": {
			{Field: "DomainName", ExpectedResult: "WIKIPEDIA.ORG", CheckType: EQUAL},
			{Field: "DomainDNSSEC", ExpectedResult: "unsigned", CheckType: EQUAL},
			{Field: "RegistrarName", ExpectedResult: "MarkMonitor Inc.", CheckType: EQUAL},
			{Field: "WhoisServer", ExpectedResult: "whois.markmonitor.com", CheckType: EQUAL},
			{Field: "NameServers", ExpectedResult: "NS2.WIKIMEDIA.ORG", CheckType: CONTAINS},
			{Field: "Emails", ExpectedResult: "abusecomplaints@markmonitor.com", CheckType: EQUAL},
			{Field: "RegistrarID", ExpectedResult: 3, CheckType: LEN},
		},
		"Registrant": {
			{Field: "Organization", ExpectedResult: "Wikimedia Foundation, Inc.", CheckType: EQUAL},
		},
	}
	parserTester(
		t,
		orgParser,
		checkParams,
		"test_data/whois_org/wikipedia.org.txt",
		".org parser",
	)

}
func parserTester(t *testing.T, targetParser *Parser, containParams map[string][]*DataForTest, pathToInput string, parserName string) {
	var fileBytes []byte
	var err error
	var text string
	var whoisInfo *Record
	var reflectWhoisInfo reflect.Value

	fileBytes, err = ioutil.ReadFile(pathToInput)
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisInfo = targetParser.Parse(text)
	reflectWhoisInfo = reflect.ValueOf(whoisInfo).Elem()
	for parserStruckField, TestDataStructs := range containParams {
		for _, TestData := range TestDataStructs {
			filedForCheck := reflectWhoisInfo.FieldByName(parserStruckField).Elem().FieldByName(TestData.Field).Interface()
			switch TestData.CheckType {
			case CONTAINS:
				assert.Contains(
					t,
					filedForCheck,
					TestData.ExpectedResult,
					"failed on "+parserName+"\n"+
						"structure "+parserStruckField+"."+TestData.Field+"\n"+
						"path to input file: "+pathToInput,
				)
			case EQUAL:
				assert.Equal(
					t,
					TestData.ExpectedResult,
					filedForCheck,
					"failed on "+parserName+"\n"+
						"structure "+parserStruckField+"."+TestData.Field+"\n"+
						"path to input file: "+pathToInput,
				)
			case LEN:
				assert.Len(
					t,
					filedForCheck,
					TestData.ExpectedResult.(int),
					"failed on "+parserName+"\n"+
						"structure "+parserStruckField+"."+TestData.Field+"\n"+
						"path to input file: "+pathToInput,
				)
			}

		}
	}
}
