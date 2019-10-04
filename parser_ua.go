package whoisparser

import (
	"regexp"
)

var uaParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No entries found for`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`Unimplemented object service`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`domain: *(.*)`),
		NameServers:    regexp.MustCompile(`nserver: *(.*)`),
		DomainStatus:   regexp.MustCompile(`(?s)nserver:.*?status: *(.*?)created`),
		CreatedDate:    regexp.MustCompile(`created: *(.*)`),
		UpdatedDate:    regexp.MustCompile(`modified: *(.*)`),
		ExpirationDate: regexp.MustCompile(`expires: *(.*)`),
		Emails:         regexp.MustCompile(`abuse-email: *(.*)`),
		RegistrarName:  regexp.MustCompile(`registrar: *(.*)`),
	},
}

func init() {
	RegisterParser(".ua", uaParser)
}
