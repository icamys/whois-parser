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
		DomainStatus:     regexp.MustCompile(`Domain Status: *(.+)`),
		ExpirationDate:     regexp.MustCompile(`Record expires on *(.+)`),
		CreatedDate:     regexp.MustCompile(`Record created on *(.+)`),
		NameServers:     regexp.MustCompile(`(?s)Domain servers in listed order:\n\s*(.*?)\n`),
	},

	adminRegex: &RegistrantRegex{
		Phone:         regexp.MustCompile(`Administrative Contact:\n\s*.*\n\s*(.*\n\s*.*)`),
		Name: regexp.MustCompile(`Administrative Contact:\n*.+\n\t(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Name: regexp.MustCompile(`Registrant:\n\s*(.*)`),
	},

	techRegex: &RegistrantRegex{
		Phone:         regexp.MustCompile(`Technical Contact:\n\s*.*\n\s*(.*\n\s*.*)`),
		Organization: regexp.MustCompile(`Technical Contact:\n.*\n\t(.*)`),
		Name:         regexp.MustCompile(`Technical Contact:\n\t(.*)`),
	},
}

func init() {
	RegisterParser(".tw", twParser)
}
