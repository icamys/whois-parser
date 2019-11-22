package whoisparser

import (
	"regexp"
)

var thParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NO MATCH`),
		RateLimit:        nil, //failed to call rate-limit for .th
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name:\s*(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar:\s*(.+)`),
		NameServers:    regexp.MustCompile(`Name Server:\s*(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC:\s*(.+)`),
		DomainStatus:   regexp.MustCompile(`Status:\s*(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated date:\s*(.+)`),
		CreatedDate:    regexp.MustCompile(`Created date:\s*(.+)`),
		ExpirationDate: regexp.MustCompile(`Domain Holder Street:\s*(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Domain Holder Organization:\s*(.+)`),
		Country:      regexp.MustCompile(`Domain Holder Country:\s*(.+)`),
		Street:       regexp.MustCompile(`Domain Holder Country:\s*(.+)`),
	},

	techRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Tech Organization:\s*(.+)`),
		Street:       regexp.MustCompile(`Tech Street:\s*(.+)`),
		Country:      regexp.MustCompile(`Tech Country:\s*(.+)`),
	},
}

func init() {
	RegisterParser(".th", thParser)
}
