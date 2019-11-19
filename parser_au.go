package whoisparser

import "regexp"

var auParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`NOT FOUND`),
		RateLimit:        nil, //failed to call rate-limit for .au
		MalformedRequest: regexp.MustCompile(`Pattern starts with improper character`),
	},

	registrarRegex: &RegistrarRegex{
		DomainDNSSEC:  regexp.MustCompile(`DNSSEC: (.+)`),
		DomainID:      regexp.MustCompile(`Registry Domain ID: *(.+)`),
		DomainName:    regexp.MustCompile(`Domain Name: *(.+)`),
		DomainStatus:  regexp.MustCompile(`(?i)Status: +(\w+).*`),
		Emails:        regexp.MustCompile(`Registrar Abuse Contact Email: (.*)`),
		NameServers:   regexp.MustCompile(`(?i)Name Server: +(.+)`),
		ReferralURL:   regexp.MustCompile(`Registrar URL: +(.*)`),
		RegistrarName: regexp.MustCompile(`Registrar Name: *(.+)`),
		UpdatedDate:   regexp.MustCompile(`Last Modified: *(.+)`),
		WhoisServer:   regexp.MustCompile(`Registrar WHOIS Server: (.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Organization: regexp.MustCompile(`Registrant: (.*)`),
		ID:           regexp.MustCompile(`Registrant Contact ID: (.*)`),
		Name:         regexp.MustCompile(`Registrant Contact Name: (.*)`),
	},

	techRegex: &RegistrantRegex{
		ID:   regexp.MustCompile(`Tech Contact ID: (.*)`),
		Name: regexp.MustCompile(`Tech Contact Name: (.*)`),
	},
}

func init() {
	RegisterParser(".au", auParser)
}
