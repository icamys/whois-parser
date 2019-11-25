package whoisparser

import (
	"regexp"
)

var cnParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No matching record.`),
		RateLimit:        nil, //failed to call rate-limit for .cn
		MalformedRequest: regexp.MustCompile(`Invalid parameter:`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainID:       regexp.MustCompile(`ROID: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Registration Time: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Expiration Time: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		ID:    regexp.MustCompile(`Registrant ID: *(.+)`),
		Name:  regexp.MustCompile(`Registrant: *(.+)`),
		Email: regexp.MustCompile(`Registrant Contact Email: *(.+)`),
	},
}

func init() {
	RegisterParser(".cn", cnParser)
}
