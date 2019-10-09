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
		DomainStatus:   regexp.MustCompile(`(?s)nserver:.*?status: *(.*?)\ncreated`),
		CreatedDate:    regexp.MustCompile(`domain:(?:.*\s)*?created: *(.*)`),
		UpdatedDate:    regexp.MustCompile(`domain:(?:.*\s)*?modified: *(.*)`),
		ExpirationDate: regexp.MustCompile(`domain:(?:.*\s)*?expires: *(.*)`),
		Emails:         regexp.MustCompile(`abuse-email: *(.*)`),
		RegistrarName:  regexp.MustCompile(`registrar: *(.*)`),
	},

	techRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:person|person-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Organization: regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:organization|organization-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Street:       regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		City:         regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:postal-code|postal-code-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Country:      regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?(?:country|country-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Phone:        regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`Technical Contacts:\n(?:.+\n)+?e-mail: *(.*?)\n`),
	},

	adminRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:person|person-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Organization: regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:organization|organization-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Street:       regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		City:         regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:postal-code|postal-code-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Country:      regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?(?:country|country-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Phone:        regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`Administrative Contacts:\n(?:.+\n)+?e-mail: *(.*?)\n`),
	},

	registrantRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:person|person-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Organization: regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:organization|organization-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Street:       regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		City:         regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:postal-code|postal-code-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Country:      regexp.MustCompile(`Registrant:\n(?:.+\n)+?(?:country|country-loc):\s+((?:.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))|(?:.{1,2}))\n`),
		Phone:        regexp.MustCompile(`Registrant:\n(?:.+\n)+?phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`Registrant:\n(?:.+\n)+?fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`Registrant:\n(?:.+\n)+?e-mail: *(.*?)\n`),
	},
}

func init() {
	RegisterParser(".ua", uaParser)
}
