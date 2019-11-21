package whoisparser

import (
	"regexp"
)

var frParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No entries found in the AFNIC Database.`),
		RateLimit:        nil, //failed to call rate-limit for .fr
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`domain: *(.+)`),
		DomainStatus:   regexp.MustCompile(`\nstatus: *(.*)`),
		RegistrarName:  regexp.MustCompile(`registrar: *(.*)`),
		ExpirationDate: regexp.MustCompile(`Expiry Date: *(.*)`),
		CreatedDate:    regexp.MustCompile(`created: *(.*)`),
		UpdatedDate:    regexp.MustCompile(`last-update: *(.*)`),
		NameServers:    regexp.MustCompile(`nserver: *(.*)`),
	},
}

func init() {
	RegisterParser(".fr", frParser)
}
