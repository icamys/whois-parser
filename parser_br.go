package whoisparser

import (
	"regexp"
)

var brParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Invalid query`),
		RateLimit:        regexp.MustCompile(`Query rate limit exceeded. Reduced information`),
		MalformedRequest: regexp.MustCompile(`No match for`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`domain:(?:.*\n)+?created: *(.*)`),
		DomainDNSSEC:   nil,
		DomainID:       nil,
		DomainName:     regexp.MustCompile(`domain: *(.*)`),
		DomainStatus:   regexp.MustCompile(`(?m)^status: *(.*)`),
		Emails:         nil,
		ExpirationDate: nil,
		NameServers:    regexp.MustCompile(`nserver: *(.*)`),
		ReferralURL:    nil,
		RegistrarID:    regexp.MustCompile(`ownerid: *(.*)`),
		RegistrarName:  regexp.MustCompile(`owner: *(.*)`),
		UpdatedDate:    regexp.MustCompile(`domain:(?:.*\n)+?changed: *(.*)`),
		WhoisServer:    nil,
	},
}

func init() {
	RegisterParser(".br", brParser)
}
