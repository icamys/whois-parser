package whoisparser

import (
	"regexp"
)

var usParser = &Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No Data Found`),
		RateLimit:        nil, //failed to call rate-limit for .us
		MalformedRequest: nil, //MalformedRequest and NoSuchDomain same
	},

	registrarRegex: &RegistrarRegex{
		DomainName:     regexp.MustCompile(`Domain Name: *(.+)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.+)`),
		WhoisServer:    regexp.MustCompile(`Registrar WHOIS Server: *(.+)`),
		ReferralURL:    regexp.MustCompile(`Registrar URL: *(.+)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.+)`),
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.+)`),
		ExpirationDate: regexp.MustCompile(`Registry Expiry Date: *(.+)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.+)`),
		RegistrarID:    regexp.MustCompile(`Registrar IANA ID: *(.+)`),
		Emails:         regexp.MustCompile(`Registrar Abuse Contact Email: *(.+)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.+)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.+)`),
	},

	registrantRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Registrant ID: *(.+)`),
		Name:         regexp.MustCompile(`Registrant Name: *(.+)`),
		Organization: regexp.MustCompile(`Registrant Organization: *(.+)`),
		Street:       regexp.MustCompile(`Registrant Street: *(.+)`),
		City:         regexp.MustCompile(`Registrant City: *(.+)`),
		Province:     regexp.MustCompile(`Registrant State/Province: *(.+)`),
		PostalCode:   regexp.MustCompile(`Registrant Postal Code: *(.+)`),
		Country:      regexp.MustCompile(`Registrant Country: *(.+)`),
		Phone:        regexp.MustCompile(`Registrant Phone: *(.+)`),
		PhoneExt:     regexp.MustCompile(`Registrant Phone Ext: *(.+)`),
		Fax:          regexp.MustCompile(`Registrant Fax: *(.+)`),
		FaxExt:       regexp.MustCompile(`Registrant Fax Ext: *(.+)`),
		Email:        regexp.MustCompile(`Registrant Email: *(.+)`),
	},

	adminRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Admin ID: *(.+)`),
		Name:         regexp.MustCompile(`Admin Name: *(.+)`),
		Organization: regexp.MustCompile(`Admin Organization: *(.+)`),
		Street:       regexp.MustCompile(`Admin Street: *(.+)`),
		City:         regexp.MustCompile(`Admin City: *(.+)`),
		Province:     regexp.MustCompile(`Admin State/Province: *(.+)`),
		PostalCode:   regexp.MustCompile(`Admin Postal Code: *(.+)`),
		Country:      regexp.MustCompile(`Admin Country: *(.+)`),
		Phone:        regexp.MustCompile(`Admin Phone: *(.+)`),
		PhoneExt:     regexp.MustCompile(`Admin Phone Ext: *(.+)`),
		Fax:          regexp.MustCompile(`Admin Fax: *(.+)`),
		FaxExt:       regexp.MustCompile(`Admin Fax Ext: *(.+)`),
		Email:        regexp.MustCompile(`Admin Email: *(.+)`),
	},

	techRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Tech ID: *(.+)`),
		Name:         regexp.MustCompile(`Tech Name: *(.+)`),
		Organization: regexp.MustCompile(`Tech Organization: *(.+)`),
		Street:       regexp.MustCompile(`Tech Street: *(.+)`),
		City:         regexp.MustCompile(`Tech City: *(.+)`),
		Province:     regexp.MustCompile(`Tech State/Province: *(.+)`),
		PostalCode:   regexp.MustCompile(`Tech Postal Code: *(.+)`),
		Country:      regexp.MustCompile(`Tech Country: *(.+)`),
		Phone:        regexp.MustCompile(`Tech Phone: *(.+)`),
		PhoneExt:     regexp.MustCompile(`Tech Phone Ext: *(.+)`),
		Fax:          regexp.MustCompile(`Tech Fax: *(.+)`),
		FaxExt:       regexp.MustCompile(`Tech Fax Ext: *(.+)`),
		Email:        regexp.MustCompile(`Tech Email: *(.+)`),
	},
}

func init() {
	RegisterParser(".us", usParser)
}
