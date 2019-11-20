package whoisparser

import (
	"regexp"
)

var kzParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Nothing found for this query`),
		RateLimit:        nil, //failed to call rate-limit for .kz
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:    regexp.MustCompile(`Domain Name\.*: *(.+)`),
		NameServers:   regexp.MustCompile(`(?i)server\.*: (.*)`),
		CreatedDate:   regexp.MustCompile(`Domain created: *(.*)`),
		DomainStatus:  regexp.MustCompile(`Domain status : *(.*)`),
		UpdatedDate:   regexp.MustCompile(`Last modified : *(.*)`),
		RegistrarName: regexp.MustCompile(`Current Registar: *(.*)`),
	},

	adminRegex: &RegistrantRegex{
		ID:    regexp.MustCompile(`Administrative Contact/Agent(?:.*\s)NIC Handle\.*: *(.*)`),
		Name:  regexp.MustCompile(`Administrative Contact/Agent(?:.*\s)+Name\.*: *(.*)`),
		Phone: regexp.MustCompile(`Administrative Contact/Agent(?:.*\s)+Phone Number\.*: *(.*)`),
		Fax:   regexp.MustCompile(`Administrative Contact/Agent(?:.*\s)+Fax Number\.*: *(.*)`),
		Email: regexp.MustCompile(`Administrative Contact/Agent(?:.*\s)+Email Address\.*: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:         regexp.MustCompile(`Organization Using Domain Name(?:.*\s)Name\.*: *(.*)`),
		Organization: regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+Organization Name\.*: *(.*)`),
		Street:       regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+Street Address\.*: *(.*)`),
		City:         regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+City\.*: *(.*)`),
		Province:     regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+State\.*: *(.*)`),
		PostalCode:   regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+Postal Code\.*: *(.*)`),
		Country:      regexp.MustCompile(`Organization Using Domain Name(?:.*\s)+Country\.*: *(.*)`),
	},
}

func init() {
	RegisterParser(".kz", kzParser)
}
