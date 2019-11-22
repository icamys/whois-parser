package whoisparser

import (
	"regexp"
)

var proParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NOT FOUND`),
		RateLimit:        nil, //failed to call rate-limit for .pro
		MalformedRequest: regexp.MustCompile(`Pattern starts with improper character`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.+)`),
		WhoisServer:    regexp.MustCompile(`Registrar WHOIS Server: *(.+)`),
		ReferralURL:    regexp.MustCompile(`Registrar URL: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Registry Expiry Date: *(.+)`),
		RegistrarID:    regexp.MustCompile(`Registrar IANA ID: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		Emails:         regexp.MustCompile(`Registrar Abuse Contact Email: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Registrant Organization: *(.+)`),
		Province:     regexp.MustCompile(`Registrant State/Province: *(.+)`),
		Country:      regexp.MustCompile(`Registrant Country: *(.+)`),
	},
}

func init() {
	RegisterParser(".pro", proParser)
}
