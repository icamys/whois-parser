package whoisparser

import (
	"regexp"
)

var inParser = &Parser{

	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`No Data Found`),
		RateLimit:        regexp.MustCompile(`Number of allowed queries exceeded`),
		MalformedRequest: regexp.MustCompile(`No Data Found`),
	},

	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`Creation Date: *(.*)`),
		DomainDNSSEC:   regexp.MustCompile(`DNSSEC: *(.*)`),
		DomainID:       regexp.MustCompile(`Registry Domain ID: *(.*)`),
		DomainName:     regexp.MustCompile(`Domain Name: *(.*)`),
		DomainStatus:   regexp.MustCompile(`Domain Status: *(.*)`),
		Emails:         regexp.MustCompile(`Registrar Abuse Contact Email: *(.*)`),
		ExpirationDate: regexp.MustCompile(`Registry Expiry Date: *(.*)`),
		NameServers:    regexp.MustCompile(`Name Server: *(.*)`),
		ReferralURL:    nil,
		RegistrarID:    regexp.MustCompile(`Registrar IANA ID: *(.*)`),
		RegistrarName:  regexp.MustCompile(`Registrar: *(.*)`),
		UpdatedDate:    regexp.MustCompile(`Updated Date: *(.*)`),
		WhoisServer:    regexp.MustCompile(`Registrar WHOIS Server: *(.*)`),
	},

	registrantRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Registrant ID: *(.*)`),
		Name:         regexp.MustCompile(`Registrant Name: *(.*)`),
		Organization: regexp.MustCompile(`Registrant Organization: *(.*)`),
		Street:       regexp.MustCompile(`Registrant Street: *(.*)`),
		StreetExt:    nil,
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

	adminRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Admin ID: *(.*)`),
		Name:         regexp.MustCompile(`Admin Name: *(.*)`),
		Organization: regexp.MustCompile(`Admin Organization: *(.*)`),
		Street:       regexp.MustCompile(`Admin Street: *(.*)`),
		StreetExt:    nil,
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

	techRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`Registry Tech ID: *(.*)`),
		Name:         regexp.MustCompile(`Tech Name: *(.*)`),
		Organization: regexp.MustCompile(`Tech Organization: *(.*)`),
		Street:       regexp.MustCompile(`Tech Street: *(.*)`),
		StreetExt:    nil,
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
}

func init() {
	RegisterParser(".in", inParser)
}
