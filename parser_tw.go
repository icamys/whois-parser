package whoisparser

import (
	"regexp"
)

var twParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No Found`),
		RateLimit:        nil, //failed to call rate-limit for .tw
		MalformedRequest: regexp.MustCompile(`網域名稱不合規定!`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Record expires on *(.+)`),
		CreatedDate:    regexp.MustCompile(`Record created on *(.+)`),
		NameServers:    regexp.MustCompile(`(?s)Domain servers in listed order:\n\s*(.*?)\n\n`),
		RegistrarName:  regexp.MustCompile(`Registration Service Provider: *(.*)`),
		ReferralURL:    regexp.MustCompile(`Registration Service URL: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Name: regexp.MustCompile(`Registrant:\n\s*(.*)`),
	},
}

func init() {
	RegisterParser(".tw", twParser)
}
