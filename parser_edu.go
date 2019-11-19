package whoisparser

import (
	"regexp"
)

var eduParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NO MATCH`),
		RateLimit:        nil, //failed to call rate-limit for .edu
		MalformedRequest: regexp.MustCompile(`Invalid domain name`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`Domain record activated: *(.+)`),
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		Emails:         regexp.MustCompile(`Administrative Contact:(\n\t.*)*`),
		ExpirationDate: regexp.MustCompile(`Domain expires: *(.+)`),
		NameServers:    regexp.MustCompile(`(?s)Name Servers:\s *(.*?)+?\n\n`),
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
		Organization: regexp.MustCompile(`Technical Contact:\n.*\n\t(.*)`),
		Name:         regexp.MustCompile(`Technical Contact:\n\t(.*)`),
	},
}

func init() {
	RegisterParser(".edu", eduParser)
}
