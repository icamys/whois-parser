package whoisparser

import (
	"regexp"
)

var deParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Status: free`),
		RateLimit:        regexp.MustCompile(`Connection resets by peer`),
		MalformedRequest: regexp.MustCompile(`Status: invalid`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:   regexp.MustCompile(`(?i)Domain: *(.+)`),
		DomainStatus: regexp.MustCompile(`(?i)Status: *(.+)`),
		NameServers:  regexp.MustCompile(`(?i)Nserver: *(.+)`),
		UpdatedDate:  regexp.MustCompile(`(?i)Changed: *(.+)`),
	},
}

func init() {
	RegisterParser(".de", deParser)
}
