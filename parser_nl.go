package whoisparser

import (
	"regexp"
)

var nlParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`is free`),
		RateLimit:        nil, //failed to call rate-limit for .nl
		MalformedRequest: regexp.MustCompile(`Error: invalid domain name`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:    regexp.MustCompile(`Domain name:\s*(.+)`),
		DomainStatus:  regexp.MustCompile(`Status:\s*(.+)`),
		DomainDNSSEC:  regexp.MustCompile(`DNSSEC:\s*(.+)`),
		NameServers:   regexp.MustCompile(`(?s)Domain nameservers:\s*(.*?)+?\n\n`),
		RegistrarName: regexp.MustCompile(`Registrar:\s*(.*)`),
	},
}

func init() {
	RegisterParser(".nl", nlParser)
}
