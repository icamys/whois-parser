package whoisparser

import (
	"regexp"
)

var ruParser = &Parser{
	lineMinLen: 5,

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No entries found for the selected source`),
		RateLimit:        regexp.MustCompile(`You have exceeded allowed connection rate`),
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?i)created: *(.+)`),
		DomainName:     regexp.MustCompile(`(?i)domain: *(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)state: *(.+)`),
		ExpirationDate: regexp.MustCompile(`(?i)free-date: *(.+)`),
		NameServers:    regexp.MustCompile(`(?i)nserver: *(.+).`),
		RegistrarName:  regexp.MustCompile(`(?i)registrar: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`(?i)org: *(.+)`),
	},
}

func init() {
	RegisterParser(".ru", ruParser)
}
