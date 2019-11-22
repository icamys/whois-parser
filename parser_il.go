package whoisparser

import (
	"regexp"
)

var ilParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`% No data was found to match the request criteria.`),
		RateLimit:        nil, //failed to call rate-limit for .il
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:    regexp.MustCompile(`domain:\s*(.+)`),
		NameServers:   regexp.MustCompile(`nserver:\s*(.+)`),
		DomainDNSSEC:  regexp.MustCompile(`DNSSEC:\s*(.+)`),
		DomainStatus:  regexp.MustCompile(`status:\s*(.+)`),
		RegistrarName: regexp.MustCompile(`registrar name:\s*(.+)`),
		Emails:        regexp.MustCompile(`registrar info:\s(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:    regexp.MustCompile(`person:\s*(.*)`),
		Fax:     regexp.MustCompile(`fax-no:\s*(.*)`),
		Phone:   regexp.MustCompile(`phone:\s*(.*)`),
		Email:   regexp.MustCompile(`person:(?:.*\s)+e-mail:\s*(.*)`),
		Address: regexp.MustCompile(`(?m)(?:.*?address *(?P<city>.*?)$.*?)\n *(?:.*?address *(?P<postalCode>.*?)$.*?)\n *(?:.*?address *(?P<country>.*?)$.*?)\nphone:`),
	},
}

func init() {
	RegisterParser(".il", ilParser)
}
