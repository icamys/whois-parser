package whoisparser

import (
	"regexp"
)

var clParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`no entries found`),
		RateLimit:        nil, //failed to call rate-limit for .cl
		MalformedRequest: regexp.MustCompile(`Invalid domain name`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:    regexp.MustCompile(`Domain name: *(.+)`),
		RegistrarName:    regexp.MustCompile(`Registrar name: *(.+)`),
		ReferralURL:    regexp.MustCompile(`Registrar URL: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation date: *(.+)`),
		ExpirationDate:    regexp.MustCompile(`Expiration date: *(.+)`),
		NameServers:    regexp.MustCompile(`Name server: *(.+)`),
		WhoisServer:    regexp.MustCompile(`Whois server \(*(.+)\)`),
	},

	registrantRegex: &RegistrantRegex{
		Name: regexp.MustCompile(`Registrant name: *(.+)`),
		Organization: regexp.MustCompile(`Registrant organisation: *(.+)`),
	},
}

func init() {
	RegisterParser(".cl", clParser)
}
