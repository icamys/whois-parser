package whoisparser

import (
	"regexp"
)

var irParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`no entries found`),
		RateLimit:        nil,
		MalformedRequest: nil, //whois result for NoSuchDomain and MalformedRequest same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`domain: *(.+)`),
		ExpirationDate: regexp.MustCompile(`expire-date: *(.+)`),
		NameServers:    regexp.MustCompile(`nserver: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`last-updated: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:     regexp.MustCompile(`\(Domain Holder\) *(.+)`),
		City:     regexp.MustCompile(`\(Domain Holder Address\)(?:.*, (.*)(?:.*, (?:.*),))`),
		Province: regexp.MustCompile(`\(Domain Holder Address\)(?:.*, (.*),)`),
		Country:  regexp.MustCompile(`\(Domain Holder Address\)(?:.*, (.*))`),
		Street:   regexp.MustCompile(`\(Domain Holder Address\)(?:.*, (.*), (?:.*, (?:.*),))`),
	},
}

func init() {
	RegisterParser(".ir", irParser)
}
