package whoisparser

import (
	"regexp"
)

var idParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`DOMAIN NOT FOUND`),
		RateLimit:        nil, //failed to call rate-limit for .id
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainID:       regexp.MustCompile(`Domain ID: *(.+)`),
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Created On: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Last Updated On: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Expiration Date: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Sponsoring Registrar Organization: *(.+)`),
		Country:      regexp.MustCompile(`Sponsoring Registrar Country: *(.+)`),
		Province:     regexp.MustCompile(`Sponsoring Registrar State/Province: *(.+)`),
		City:         regexp.MustCompile(`Sponsoring Registrar City: *(.+)`),
		PostalCode:   regexp.MustCompile(`Sponsoring Registrar Postal Code: *(.+)`),
		Phone:        regexp.MustCompile(`Sponsoring Registrar Phone: *(.+)`),
		Fax:          regexp.MustCompile(`Sponsoring Registrar FAX: *(.+)`),
		Email:        regexp.MustCompile(`Sponsoring Registrar Contact Email: *(.+)`),
	},
}

func init() {
	RegisterParser(".id", idParser)
}
