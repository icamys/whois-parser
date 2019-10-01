package whoisparser

import (
	"regexp"
)

var orgParser = &Parser{
	lineMinLen: 5,

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NOT FOUND`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`Not a valid domain search pattern`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?i)Creation Date: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.+)`),
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)Domain status: *(.+)`),
		Emails:         regexp.MustCompile(`(?i)Registrar Abuse Contact Email: *(` + EmailRegex + `)`),
		ExpirationDate: regexp.MustCompile(`Registrar Registration Expiration Date: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		RegistrarID:    regexp.MustCompile(`Registrar IANA ID: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`(?i)Updated Date: *(.+)`),
		WhoisServer:    regexp.MustCompile(`(?i)Registrar WHOIS Server: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`(?i)Registrant Organization: *(.+)`),
		Province:     regexp.MustCompile(`(?i)Registrant State/Province: *(.+)`),
		Country:      regexp.MustCompile(`(?i)Registrant Country: *(.+)`),
	},
}

func init() {
	RegisterParser(".org", orgParser)
}
