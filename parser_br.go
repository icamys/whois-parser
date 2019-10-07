package whoisparser

import (
	"regexp"
)

var brParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No entries found for the selected source`),
		RateLimit:        regexp.MustCompile(`You have exceeded allowed connection rate`),
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    nil,
		DomainDNSSEC:   nil,
		DomainID:       nil,
		DomainName:     nil,
		DomainStatus:   nil,
		Emails:         nil,
		ExpirationDate: nil,
		NameServers:    nil,
		ReferralURL:    nil,
		RegistrarID:    nil,
		RegistrarName:  nil,
		UpdatedDate:    nil,
		WhoisServer:    nil,
	},
}

func init() {
	RegisterParser(".br", brParser)
}
