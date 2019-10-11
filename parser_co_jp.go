package whoisparser

import (
	"regexp"
)

var coJpParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No match!`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`<JPRS WHOIS HELP>`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`\[Registered Date\] *(.+)`),
		DomainName:     regexp.MustCompile(`(?i)\[Domain Name] *(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)\[Status] *(.+)`),
		Emails:         regexp.MustCompile(`(?i)(` + EmailRegex + `)`),
		ExpirationDate: regexp.MustCompile(`\[State\] *(.+)`),
		NameServers:    regexp.MustCompile(`(?i)\[Name Server] *(.+)`),
		UpdatedDate:    regexp.MustCompile(`\[Last Update\] *(.+)`),
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
	RegisterParser(".co.jp", coJpParser)
}
