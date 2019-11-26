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
		Emails:         regexp.MustCompile(`Administrative Contact:(?:.*\s)+(?:\s*)(.*@.*)(?:\s*)Tech`),
		ExpirationDate: regexp.MustCompile(`Domain expires: *(.+)`),
		NameServers:    regexp.MustCompile(`(?s)Name Servers:\s*(.*?)\n\n`),
		UpdatedDate:    regexp.MustCompile(`Domain record last updated: *(.+)`),
		WhoisServer:    regexp.MustCompile(`available at: (.*)`),
	},

	adminRegex: &RegistrantRegex{
		Name:         regexp.MustCompile(`Administrative Contact:\s*(.*)`),
		Organization: regexp.MustCompile(`Administrative Contact:\s*.*\s*(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Registrant:(?:.*\s.)(.*)`),
	},

	techRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Technical Contact:(?:\n.*\n\t)(.*)`),
		Name:         regexp.MustCompile(`Technical Contact:\n\t(.*)`),
		Email:         regexp.MustCompile(`Technical Contact:(?:.*\s)+(?:\s*)(.*@.*)(?:\s*)`),
	},
}

func init() {
	RegisterParser(".edu", eduParser)
}
