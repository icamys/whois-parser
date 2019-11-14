package whoisparser

import "regexp"

// Registrar is a structure that stores parsed registrar info.
// Registrar registers the registrant.
type Registrar struct {
	CreatedDate    string `json:"created_date,omitempty"`
	DomainDNSSEC   string `json:"domain_dnssec,omitempty"`
	DomainID       string `json:"domain_id,omitempty"`
	DomainName     string `json:"domain_name,omitempty"`
	DomainStatus   string `json:"domain_status,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
	NameServers    string `json:"name_servers,omitempty"`
	ReferralURL    string `json:"referral_url,omitempty"`
	RegistrarID    string `json:"registrar_id,omitempty"`
	RegistrarName  string `json:"registrar_name,omitempty"`
	UpdatedDate    string `json:"updated_date,omitempty"`
	WhoisServer    string `json:"whois_server,omitempty"`
	Emails         string `json:"emails,omitempty"`
}

// RegistrarRegex struct with regular expressions used to parse Registrar
type RegistrarRegex struct {
	CreatedDate    *regexp.Regexp
	DomainDNSSEC   *regexp.Regexp
	DomainID       *regexp.Regexp
	DomainName     *regexp.Regexp
	DomainStatus   *regexp.Regexp
	Emails         *regexp.Regexp
	ExpirationDate *regexp.Regexp
	NameServers    *regexp.Regexp
	ReferralURL    *regexp.Regexp
	RegistrarID    *regexp.Regexp
	RegistrarName  *regexp.Regexp
	UpdatedDate    *regexp.Regexp
	WhoisServer    *regexp.Regexp
}
