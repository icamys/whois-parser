package whoisparser

import (
	"regexp"
)

var jpParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No match!`),
		RateLimit:        regexp.MustCompile(`Cannot process your search request`),
		MalformedRequest: regexp.MustCompile(`<JPRS WHOIS HELP>`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?i)\[Created on] *(.+)`),
		DomainName:     regexp.MustCompile(`(?i)\[Domain Name] *(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)\[Status] *(.+)`),
		Emails:         regexp.MustCompile(`(?i)(` + EmailRegex + `)`),
		ExpirationDate: regexp.MustCompile(`(?i)\[Expires on] *(.+)`),
		NameServers:    regexp.MustCompile(`(?i)\[Name Server] *(.+)`),
		UpdatedDate:    regexp.MustCompile(`(?i)\[Last Updated] *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:         regexp.MustCompile(`(?i)\[Registrant] *(.+)`),
		Organization: regexp.MustCompile(`(?i)\[Organization] *(.+)`),
	},

	adminRegex: &RegistrantRegex{
		ID: regexp.MustCompile(`(?i)\[Administrative Contact] *(.+)`),
	},

	techRegex: &RegistrantRegex{
		ID: regexp.MustCompile(`(?i)\[Technical Contact] *(.+)`),
	},
}

func init() {
	RegisterParser(".jp", jpParser)
}
