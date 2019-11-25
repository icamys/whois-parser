package whoisparser

import (
	"regexp"
)

var arParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`El dominio no se encuentra registrado en NIC Argentina`),
		RateLimit:        nil, //failed to call rate-limit for .ar
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`domain:\s*(.+)`),
		RegistrarName:  regexp.MustCompile(`registrar:\s*(.+)`),
		CreatedDate:    regexp.MustCompile(`registered:\s*(.+)`),
		UpdatedDate:    regexp.MustCompile(`domain:(?:.*\s)+changed:\s*(.*)\nexpire`),
		ExpirationDate: regexp.MustCompile(`expire:\s*(.+)`),
		NameServers:    regexp.MustCompile(`nserver:\s*(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Name: regexp.MustCompile(`name:\s*(.+)`),
		ID:   regexp.MustCompile(`registrant:\s*(.+)`),
	},
}

func init() {
	RegisterParser(".ar", arParser)
}
