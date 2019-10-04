package whoisparser

import (
	"regexp"
)

var itParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Status: *AVAILABLE`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`Invalid request`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?m)^Created: *(.*?)$`),
		DomainDNSSEC:   regexp.MustCompile(`(?sm)Registrar(?:.*DNSSEC: *(.*?))\n\n`),
		DomainName:     regexp.MustCompile(`Domain: *(.*)`),
		DomainStatus:   regexp.MustCompile(`Status: *(.*)`),
		ExpirationDate: regexp.MustCompile(`(?m)^Expire Date: *(.*)`),
		NameServers:    regexp.MustCompile(`(?sm)Nameservers\n(.*)\n\n`),
		RegistrarName:  regexp.MustCompile(`(?sm)Registrar(?:.*Name: *(.*?)$.*)\n\n`),
		UpdatedDate:    regexp.MustCompile(`(?m)^Last Update: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		SingleRegexAddress: true,
		Address:            regexp.MustCompile(`(?ms)Registrant(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
		Organization:       regexp.MustCompile(`(?ms)Registrant(?:.*?Organization: *(.*?)$.*)\n\n`),
	},
	adminRegex: &RegistrantRegex{
		SingleRegexAddress: true,
		Address:            regexp.MustCompile(`(?ms)Admin Contact(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
		Organization:       regexp.MustCompile(`(?ms)Admin Contact(?:.*?Organization: *(.*?)$.*)\n\n`),
		Name:               regexp.MustCompile(`(?ms)Admin Contact(?:.*?Name: *(.*?)$.*)\n\n`),
	},
	techRegex: &RegistrantRegex{
		SingleRegexAddress: true,
		Address:            regexp.MustCompile(`(?ms)Technical Contacts(?:.*?Address: *(?P<street>.*?)$.*?)\n *(?P<city>.*?)\n *(?P<postalCode>.*?)\n *(?P<province>.*?)\n *(?P<country>.*?)\n.*?Creat`),
		Organization:       regexp.MustCompile(`(?ms)Technical Contacts(?:.*?Organization: *(.*?)$.*)\n\n`),
		Name:               regexp.MustCompile(`(?ms)Technical Contacts(?:.*?Name: *(.*?)$.*)\n\n`),
	},
}

func init() {
	RegisterParser(".it", itParser)
}
