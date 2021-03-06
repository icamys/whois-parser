package whoisparser

import (
	"regexp"
)

var trParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No match found for`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`Please enter a name`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`Created on\.*: *(.*)\.`),
		DomainDNSSEC:   nil,
		DomainID:       nil,
		DomainName:     regexp.MustCompile(`Domain Name: *(.*)`),
		DomainStatus:   nil,
		Emails:         nil,
		ExpirationDate: regexp.MustCompile(`Expires on\.*: *(.*)\.`),
		NameServers:    nil,
		ReferralURL:    nil,
		RegistrarID:    nil,
		RegistrarName:  regexp.MustCompile(`Registrar:\n(?:.+\n)*?(?:Organization Name *: *(.*))`),
		UpdatedDate:    nil,
		WhoisServer:    nil,
	},

	registrantRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Registrant:(?:.*\n) *(.*)`),
		Organization: nil,
		Street:       regexp.MustCompile(`Registrant:(?:.*\n){2} *(.*)`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`Registrant:(?:.*\n){4} *(.*),`),
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Registrant:(?:.*\n){4}.*,(.*)`),
		Country:      regexp.MustCompile(`Registrant:(?:.*\n){5} *(.*)`),
		Phone:        regexp.MustCompile(`Registrant:(?:.*\n){7} *(.*)`),
		PhoneExt:     nil,
		Fax:          nil,
		FaxExt:       nil,
		Email:        regexp.MustCompile(`Registrant:(?:.*\n){6} *(.*)`),
	},

	adminRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Administrative Contact:\n(?:.+\n)*?(?:Person *: *(.*))`),
		Organization: regexp.MustCompile(`Administrative Contact:\n(?:.+\n)*?(?:Organization Name *: *(.*))`),
		Street:       regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Address *: *(.*))`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2} *(.*),)`),
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2}.*,(.*))`),
		Country:      regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){3} *(.*))`),
		Phone:        regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Phone *: *(.*))`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Administrative Contact:\n(?:.+\n)+?(?:Fax *: *(.*))`),
		FaxExt:       nil,
		Email:        nil,
	},

	techRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Person *: *(.*))`),
		Organization: regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Organization Name *: *(.*))`),
		Street:       regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Address *: *(.*))`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2}(.*),)`),
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2}.*,(.*))`),
		Country:      regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){3}(.*))`),
		Phone:        regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Phone *: *(.*))`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Technical Contact:\n(?:.+\n)+?(?:Fax *: *(.*))`),
		FaxExt:       nil,
		Email:        nil,
	},

	billRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Person *: *(.*))`),
		Organization: regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Organization Name *: *(.*))`),
		Street:       regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Address *: *(.*))`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2}(.*),)`),
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){2}.*,(.*))`),
		Country:      regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Address *: *(?:.*\n){3}(.*))`),
		Phone:        regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Phone *: *(.*))`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Billing Contact:\n(?:.+\n)+?(?:Fax *: *(.*))`),
		FaxExt:       nil,
		Email:        nil,
	},
}

func init() {
	RegisterParser(".tr", trParser)
}
