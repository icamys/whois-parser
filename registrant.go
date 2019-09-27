package whoisparser

import "regexp"

// Registrant is registered by the registrar
type Registrant struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Street       string `json:"street,omitempty"`
	StreetExt    string `json:"street_ext,omitempty"`
	City         string `json:"city,omitempty"`
	Province     string `json:"province,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Country      string `json:"country,omitempty"`
	Phone        string `json:"phone,omitempty"`
	PhoneExt     string `json:"phone_ext,omitempty"`
	Fax          string `json:"fax,omitempty"`
	FaxExt       string `json:"fax_ext,omitempty"`
	Email        string `json:"email,omitempty"`
}

// RegistrantRegex struct with regular expressions used to parse Registrant
type RegistrantRegex struct {
	ID           *regexp.Regexp
	Name         *regexp.Regexp
	Organization *regexp.Regexp
	Street       *regexp.Regexp
	StreetExt    *regexp.Regexp
	City         *regexp.Regexp
	Province     *regexp.Regexp
	PostalCode   *regexp.Regexp
	Country      *regexp.Regexp
	Phone        *regexp.Regexp
	PhoneExt     *regexp.Regexp
	Fax          *regexp.Regexp
	FaxExt       *regexp.Regexp
	Email        *regexp.Regexp
}
