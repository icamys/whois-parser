package whoisparser

import (
	"regexp"
)

var plParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No information available about domain name`),
		RateLimit:        regexp.MustCompile(`request limit exceeded`),
		MalformedRequest: regexp.MustCompile(`Incorrect domain name`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?m)^created: *(.*)`),
		DomainDNSSEC:   regexp.MustCompile(`dnssec: *(.*)`),
		DomainName:     regexp.MustCompile(`DOMAIN NAME: *(.+)`),
		ExpirationDate: regexp.MustCompile(`option expiration date: *(.*)`),
		NameServers:    regexp.MustCompile(`(?s)nameservers: *(.*?) *created`),
		UpdatedDate:    regexp.MustCompile(`(?m)^last modified: *(.*)`),
	},
}

func init() {
	RegisterParser(".pl", plParser)
}
