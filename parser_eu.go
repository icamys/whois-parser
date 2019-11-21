package whoisparser

import (
	"regexp"
)

var euParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Status: AVAILABLE`),
		RateLimit:        nil, //failed to call rate-limit for .eu
		MalformedRequest: regexp.MustCompile(`Invalid pattern`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:    regexp.MustCompile(`Domain: *(.+)`),
		RegistrarName: regexp.MustCompile(`Registrar:\n\s*Name:\s*(.*)`),
		ReferralURL:   regexp.MustCompile(`Registrar:(?:.*\s.)+Website\.*: *(.*)`),
		NameServers:   regexp.MustCompile(`(?s)Name servers:\n\s*(.*?)+?\n\n`),
	},

	techRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Technical:(?:.*\s.)+Organisation\.*: *(.*)`),
		Email:        regexp.MustCompile(`Technical:(?:.*\s.)+Email\.*: *(.*)`),
	},
}

func init() {
	RegisterParser(".eu", euParser)
}
