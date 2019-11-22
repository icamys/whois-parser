package whoisparser

import (
	"regexp"
)

var bizParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No Data Found`),
		RateLimit:        nil, //failed to call rate-limit for .biz
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
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Province:     regexp.MustCompile(`Registrant State/Province: *(.+)`),
		Organization: regexp.MustCompile(`Registrant Organization: *(.+)`),
		Country:      regexp.MustCompile(`Registrant Country: *(.+)`),
	},
}

func init() {
	RegisterParser(".biz", bizParser)
}
