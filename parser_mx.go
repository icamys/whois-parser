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
		DomainName:    regexp.MustCompile(`Domain Name:\s*(.+)`),
		RegistrarName:    regexp.MustCompile(`Registrar:\s*(.+)`),
		ExpirationDate:    regexp.MustCompile(`Expiration Date:\s*(.+)`),
		UpdatedDate:    regexp.MustCompile(`Last Updated On:\s*(.+)`),
		ReferralURL:    regexp.MustCompile(`URL:\s*(.+)`),
	},

	adminRegex: &RegistrantRegex{
		//Name:         regexp.MustCompile(`Administrative Contact:\n\t(.+)`),
		//Organization: regexp.MustCompile(`Administrative Contact:\n*.+\n\t(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		//Organization: regexp.MustCompile(`(?m)Registrant:\n\t(.*)`),
	},

	techRegex: &RegistrantRegex{
		//Organization: regexp.MustCompile(`Technical Contact:\n.*\n\t(.*)`),
		//Name:         regexp.MustCompile(`Technical Contact:\n\t(.*)`),
	},
}

func init() {
	RegisterParser(".mx", mxParser)
}
