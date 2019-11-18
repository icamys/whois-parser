package whoisparser

import (
	"regexp"
)

var eduParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NO MATCH`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`Invalid domain name`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`Domain record activated: *(.+)`),
		DomainDNSSEC:   nil,
		DomainID:       nil,
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainStatus:   nil,
		Emails:         nil,
		ExpirationDate: regexp.MustCompile(`Domain expires: *(.+)`),
		NameServers:    regexp.MustCompile(`(?s)Name Servers:\s *(.*?)+?\n\n`),
		ReferralURL:    nil,
		RegistrarID:    nil,
		RegistrarName:  nil,
		UpdatedDate:    regexp.MustCompile(`Domain record last updated: *(.+)`),
		WhoisServer:    regexp.MustCompile(`available at: (.*)`),
	},

	adminRegex: &RegistrantRegex{
		Name:         regexp.MustCompile(`Administrative Contact:\n\t(.+)`),
		Organization: regexp.MustCompile(`Administrative Contact:\n*.+\n\t(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`(?m)Registrant:\n\t(.*)`),
	},

	techRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Technical Contact:\n*.+\n\t(.*)`),
		Name:         regexp.MustCompile(`Technical Contact:\n\t(\n*.+)`)},
}

func init() {
	RegisterParser(".edu", eduParser)
}
