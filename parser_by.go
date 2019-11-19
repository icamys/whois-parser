package whoisparser

import (
	"regexp"
)

var byParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Object does not exist`),
		RateLimit:        nil, //failed to call rate-limit for .by
		MalformedRequest: regexp.MustCompile(`Parameter value syntax error`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Expiration Date: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:         regexp.MustCompile(`Person: *(.+)`),
		Country:      regexp.MustCompile(`Country: *(.+)`),
		Email:        regexp.MustCompile(`Email: *(.+)`),
		Phone:        regexp.MustCompile(`Phone: *(.+)`),
		ID:           regexp.MustCompile(`Registration or other identification number: *(.+)`),
		Organization: regexp.MustCompile(`Org: *(.+)`),
	},
}

func init() {
	RegisterParser(".by", byParser)
}
