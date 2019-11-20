package whoisparser

import (
	"regexp"
)

var zaParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`Available`),
		RateLimit:        nil, //failed to call rate-limit for .za
		MalformedRequest: regexp.MustCompile(`No information was found matching that query`),
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.+)`),
		WhoisServer:    regexp.MustCompile(`Registrar WHOIS Server: *(.+)`),
		ReferralURL:    regexp.MustCompile(`Registrar URL: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Registrar Registration Expiration Date: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		Emails:         regexp.MustCompile(`Registrar Abuse Contact Email: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
	},

	adminRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Admin ID: *(.*)`),
		Name:         regexp.MustCompile(`Admin Name: *(.*)`),
		Organization: regexp.MustCompile(`Admin Organization: *(.*)`),
		Street:       regexp.MustCompile(`Admin Street: *(.*)`),
		City:         regexp.MustCompile(`Admin City: *(.*)`),
		Province:     regexp.MustCompile(`Admin State/Province: *(.*)`),
		PostalCode:   regexp.MustCompile(`Admin Postal Code: *(.*)`),
		Country:      regexp.MustCompile(`Admin Country: *(.*)`),
		Phone:        regexp.MustCompile(`Admin Phone: *(.*)`),
		PhoneExt:     regexp.MustCompile(`Admin Phone Ext: *(.*)`),
		Fax:          regexp.MustCompile(`Admin Fax: *(.*)`),
		FaxExt:       regexp.MustCompile(`Admin Fax Ext: *(.*)`),
		Email:        regexp.MustCompile(`Admin Email: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Registrant ID: *(.*)`),
		Name:         regexp.MustCompile(`Registrant Name: *(.*)`),
		Organization: regexp.MustCompile(`Registrant Organization: *(.*)`),
		Street:       regexp.MustCompile(`Registrant Street: *(.*)`),
		City:         regexp.MustCompile(`Registrant City: *(.*)`),
		Province:     regexp.MustCompile(`Registrant State/Province: *(.*)`),
		PostalCode:   regexp.MustCompile(`Registrant Postal Code: *(.*)`),
		Country:      regexp.MustCompile(`Registrant Country: *(.*)`),
		Phone:        regexp.MustCompile(`Registrant Phone: *(.*)`),
		PhoneExt:     regexp.MustCompile(`Registrant Phone Ext: *(.*)`),
		Fax:          regexp.MustCompile(`Registrant Fax: *(.*)`),
		FaxExt:       regexp.MustCompile(`Registrant Fax Ext: *(.*)`),
		Email:        regexp.MustCompile(`Registrant Email: *(.*)`),
	},

	techRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Tech ID: *(.*)`),
		Name:         regexp.MustCompile(`Tech Name: *(.*)`),
		Organization: regexp.MustCompile(`Tech Organization: *(.*)`),
		Street:       regexp.MustCompile(`Tech Street: *(.*)`),
		City:         regexp.MustCompile(`Tech City: *(.*)`),
		Province:     regexp.MustCompile(`Tech State/Province: *(.*)`),
		PostalCode:   regexp.MustCompile(`Tech Postal Code: *(.*)`),
		Country:      regexp.MustCompile(`Tech Country: *(.*)`),
		Phone:        regexp.MustCompile(`Tech Phone: *(.*)`),
		PhoneExt:     regexp.MustCompile(`Tech Phone Ext: *(.*)`),
		Fax:          regexp.MustCompile(`Tech Fax: *(.*)`),
		FaxExt:       regexp.MustCompile(`Tech Fax Ext: *(.*)`),
		Email:        regexp.MustCompile(`Tech Email: *(.*)`),
	},

	billRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Billing ID: *(.*)`),
		Name:         regexp.MustCompile(`Billing Name: *(.*)`),
		Organization: regexp.MustCompile(`Billing Organization: *(.*)`),
		Street:       regexp.MustCompile(`Billing Street: *(.*)`),
		City:         regexp.MustCompile(`Billing City: *(.*)`),
		Province:     regexp.MustCompile(`Billing State/Province: *(.*)`),
		PostalCode:   regexp.MustCompile(`Billing Postal Code: *(.*)`),
		Country:      regexp.MustCompile(`Billing Country: *(.*)`),
		Phone:        regexp.MustCompile(`Billing Phone: *(.*)`),
		PhoneExt:     regexp.MustCompile(`Billing Phone Ext: *(.*)`),
		Fax:          regexp.MustCompile(`Billing Fax: *(.*)`),
		FaxExt:       regexp.MustCompile(`Billing Fax Ext: *(.*)`),
		Email:        regexp.MustCompile(`Billing Email: *(.*)`),
	},
}

func init() {
	RegisterParser(".za", zaParser)
}
