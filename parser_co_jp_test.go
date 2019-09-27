package whoisparser

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParserCoJp(t *testing.T) {
	var fileBytes []byte
	var err error
	var text string
	var whoisInfo *Record

	fileBytes, err = ioutil.ReadFile("test_data/whois_co_jp/jal.co.jp.txt")
	assert.NoError(t, err, "failed to open file with test data")

	text = string(fileBytes)

	whoisInfo = coJpParser.Parse(text)
	assert.NoError(t, err, "failed to open file with test data")

	assert.Contains(t, whoisInfo.Registrar.DomainName, "JAL.CO.JP")
	assert.Contains(t, whoisInfo.Registrar.CreatedDate, "1994/08/04")
	assert.Contains(t, whoisInfo.Registrar.ExpirationDate, "Connected (2020/08/31)")
	assert.Len(t, whoisInfo.Registrar.NameServers, 45)
	assert.Contains(t, whoisInfo.Registrar.NameServers, "dns-a.iij.ad.jp")
	assert.Contains(t, whoisInfo.Registrar.NameServers, "ns01.jal.co.jp")
	assert.Contains(t, whoisInfo.Registrar.NameServers, "ns02.jal.co.jp")
	assert.Contains(t, whoisInfo.Registrar.UpdatedDate, "2019/09/01 01:07:02 (JST)")
	assert.Equal(t, whoisInfo.Registrant.Organization, "Japan Airlines Co., Ltd.")
	assert.Equal(t, whoisInfo.Admin.ID, "YS32616JP")
	assert.Len(t, whoisInfo.Tech.ID, 38)
	assert.Contains(t, whoisInfo.Tech.ID, "TK22256JP")
	assert.Contains(t, whoisInfo.Tech.ID, "KT15543JP")
	assert.Contains(t, whoisInfo.Tech.ID, "MY9415JP")
	assert.Contains(t, whoisInfo.Tech.ID, "SK12923JP")
}
