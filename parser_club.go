package whoisparser

import (
	"regexp"
)

var clubParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No Data Found`),
		RateLimit:        nil, //failed to call rate-limit for .club
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.+)`),
		WhoisServer:    regexp.MustCompile(`Registrar WHOIS Server: *(.+)`),
		ReferralURL:    regexp.MustCompile(`Registrar URL: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Registry Expiry Date: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		RegistrarID:    regexp.MustCompile(`Registrar IANA ID: *(.+)`),
		Emails:         regexp.MustCompile(`Registrar Abuse Contact Email: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Registrant Organization: *(.+)`),
		Province:     regexp.MustCompile(`Registrant State/Province: *(.+)`),
		Country:      regexp.MustCompile(`Registrant Country: *(.+)`),
	},
}

func init() {
	RegisterParser(".club", clubParser)
}
