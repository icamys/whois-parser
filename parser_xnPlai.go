package whoisparser

import (
	"regexp"
)

var xnPlaiParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No entries found for the selected source`),
		RateLimit:        nil, //failed to call rate-limit for .xn--plai
		MalformedRequest: regexp.MustCompile(`Invalid request.`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`domain:\s*(.+)`),
		NameServers:    regexp.MustCompile(`nserver:\s*(.+)`),
		DomainStatus:   regexp.MustCompile(`state:\s*(.+)`),
		RegistrarName:  regexp.MustCompile(`registrar:\s*(.+)`),
		ReferralURL:    regexp.MustCompile(`admin-contact:\s*(.+)`),
		CreatedDate:    regexp.MustCompile(`created:\s*(.+)`),
		ExpirationDate: regexp.MustCompile(`paid-till:\s*(.+)`),
		UpdatedDate:    regexp.MustCompile(`Last updated on\s*(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`org:\s*(.+)`),
	},
}

func init() {
	RegisterParser(".xn--plai", xnPlaiParser)
}
