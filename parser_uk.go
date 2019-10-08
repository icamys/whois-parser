package whoisparser

import (
	"regexp"
)

var ukParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No match for`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`This domain cannot be registered because it contravenes`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`Relevant dates:\s *Registered on: *(.*)`),
		DomainDNSSEC:   nil,
		DomainID:       nil,
		DomainName:     regexp.MustCompile(`Domain name:\s *(.*)`),
		DomainStatus:   regexp.MustCompile(`Registration status:\s *(.*)`),
		Emails:         nil,
		ExpirationDate: regexp.MustCompile(`Relevant dates:(?:.*\s)+Expiry date: *(.*)`),
		NameServers:    regexp.MustCompile(`(?s)Name servers:\s *(.*?)+?\n\n`),
		ReferralURL:    nil,
		RegistrarID:    nil,
		RegistrarName:  regexp.MustCompile(`Registrar:\s *(.*)`),
		UpdatedDate:    regexp.MustCompile(`Relevant dates:(?:.*\s)+Last updated: *(.*)`),
		WhoisServer:    nil,
	},
}

func init() {
	RegisterParser(".uk", ukParser)
}
