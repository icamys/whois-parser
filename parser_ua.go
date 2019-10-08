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
		// (?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]) - negative lookahead alternative
		ID:           nil,
		Name:         regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:person|person-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Organization: regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:organization|organization-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Street:       regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		City:         regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:postal-code|postal-code-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Country:      regexp.MustCompile(`Technical Contacts:(?:.*\n)+?(?:country|country-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Phone:        regexp.MustCompile(`(?s)Technical Contacts:.*phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`(?s)Technical Contacts:.*fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`(?s)Technical Contacts:.*e-mail: *(.*?)\n`),
	},

	adminRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:person|person-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Organization: regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:organization|organization-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Street:       regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		City:         regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:postal-code|postal-code-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Country:      regexp.MustCompile(`Administrative Contacts:(?:.*\n)+?(?:country|country-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Phone:        regexp.MustCompile(`(?s)Administrative Contacts:.*phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`(?s)Administrative Contacts:.*fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`(?s)Administrative Contacts:.*e-mail: *(.*?)\n`),
	},

	registrantRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`Registrant:(?:.*\n)+?(?:person|person-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Organization: regexp.MustCompile(`Registrant:(?:.*\n)+?(?:organization|organization-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Street:       regexp.MustCompile(`Registrant:(?:.*\n)+?(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		City:         regexp.MustCompile(`Registrant:(?:.*\n)+?(?:(?:address|address-loc):.*\n)(?:address|address-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		StreetExt:    nil,
		Province:     nil,
		PostalCode:   regexp.MustCompile(`Registrant:(?:.*\n)+?(?:postal-code|postal-code-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Country:      regexp.MustCompile(`Registrant:(?:.*\n)+?(?:country|country-loc):\s+(.+(?:[^n][^\\][^a]|[^n][^\\]a|[^n]\\a|[^n]\\[^a]|n\\[^a]|n[^\\][^a]))\n`),
		Phone:        regexp.MustCompile(`(?s)Registrant:.*phone: *(.*?)\n`),
		PhoneExt:     nil,
		Fax:          regexp.MustCompile(`(?s)Registrant:.*fax: *(.*?)\n`),
		FaxExt:       nil,
		Email:        regexp.MustCompile(`(?s)Registrant:.*e-mail: *(.*?)\n`),
	},
}

func init() {
	RegisterParser(".ua", uaParser)
}
