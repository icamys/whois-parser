package whoisparser

import (
	"regexp"
)

var mxParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No_Se_Encontro_El_Objeto/Object_Not_Found`),
		RateLimit:        nil, //failed to call rate-limit for .mx
		MalformedRequest: regexp.MustCompile(`Cadena_Invalida/Invalid_String`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name:\s*(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar:\s*(.+)`),
		ExpirationDate: regexp.MustCompile(`Expiration Date:\s*(.+)`),
		UpdatedDate:    regexp.MustCompile(`Last Updated On:\s*(.+)`),
		ReferralURL:    regexp.MustCompile(`URL:\s*(.+)`),
		NameServers:    regexp.MustCompile(`DNS: *(.*)`),
		DomainDNSSEC:   regexp.MustCompile(`DS Record: *(.*)`),
	},

	adminRegex: &RegistrantRegex{
		Name:     regexp.MustCompile(`Administrative Contact:(?:.*\s*)Name\.*: *(.*)`),
		City:     regexp.MustCompile(`Administrative Contact:(?:.*\s.)+City\.*: *(.*)`),
		Province: regexp.MustCompile(`Administrative Contact:(?:.*\s.)+State\.*: *(.*)`),
		Country:  regexp.MustCompile(`Administrative Contact:(?:.*\s.)+Country\.*: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		Name:     regexp.MustCompile(`Registrant:(?:.*\s*)Name\.*: *(.*)`),
		City:     regexp.MustCompile(`Registrant:(?:.*\s.)+City\.*: *(.*)`),
		Province: regexp.MustCompile(`Registrant:(?:.*\s.)+State\.*: *(.*)`),
		Country:  regexp.MustCompile(`Registrant:(?:.*\s.)+Country\.*: *(.*)`),
	},

	techRegex: &RegistrantRegex{
		Name:     regexp.MustCompile(`Technical Contact:(?:.*\s*)Name\.*: *(.*)`),
		City:     regexp.MustCompile(`Technical Contact:(?:.*\s.)+City\.*: *(.*)`),
		Province: regexp.MustCompile(`Technical Contact:(?:.*\s.)+State\.*: *(.*)`),
		Country:  regexp.MustCompile(`Technical Contact:(?:.*\s.)+Country\.*: *(.*)`),
	},

	billRegex: &RegistrantRegex{
		Name:     regexp.MustCompile(`Billing Contact:(?:.*\s*)Name\.*: *(.*)`),
		City:     regexp.MustCompile(`Billing Contact:(?:.*\s.)+City\.*: *(.*)`),
		Province: regexp.MustCompile(`Billing Contact:(?:.*\s.)+State\.*: *(.*)`),
		Country:  regexp.MustCompile(`Billing Contact:(?:.*\s.)+Country\.*: *(.*)`),
	},
}

func init() {
	RegisterParser(".mx", mxParser)
}
