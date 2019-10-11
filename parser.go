package whoisparser

import (
	"regexp"
	"strings"
)

// Parser structure with registrar and registrant sections
type Parser struct {
	errorRegex      *ParseErrorRegex
	registrarRegex  *RegistrarRegex
	registrantRegex *RegistrantRegex
	adminRegex      *RegistrantRegex
	techRegex       *RegistrantRegex
	billRegex       *RegistrantRegex
}

// Parse parses whois text
func (p *Parser) Parse(text string) *Record {
	record := &Record{
		ErrCode: p.getErrCode(text),
	}

	if record.ErrCode != ErrCodeNoError {
		return record
	}

	record.Registrar = parseRegistrar(&text, p.registrarRegex)
	record.Registrant = parseRegistrant(&text, p.registrantRegex)
	record.Admin = parseRegistrant(&text, p.adminRegex)
	record.Tech = parseRegistrant(&text, p.techRegex)
	record.Bill = parseRegistrant(&text, p.billRegex)

	return record
}

// getErrCode searches for request errors in provided text and returns request error flag
func (p *Parser) getErrCode(text string) ErrCode {
	if len(text) == 0 {
		return ErrCodeEmptyWhois
	}

	if strings.Contains(text, "This TLD has no whois server, but you can access the whois database at") {
		return ErrCodeTldHasNoServer
	}

	if p.errorRegex == nil {
		return ErrCodeNoErrorRegex
	}

	if p.errorRegex.MalformedRequest != nil && len(p.errorRegex.MalformedRequest.FindString(text)) > 0 {
		return ErrCodeMalformedRequest
	}

	if p.errorRegex.NoSuchDomain != nil && len(p.errorRegex.NoSuchDomain.FindString(text)) > 0 {
		return ErrCodeNoSuchDomain
	}

	if p.errorRegex.RateLimit != nil && len(p.errorRegex.RateLimit.FindString(text)) > 0 {
		return ErrCodeRequestRateLimit
	}

	return ErrCodeNoError
}

func parseRegistrar(text *string, re *RegistrarRegex) *Registrar {
	if re == nil {
		return nil
	}

	registrar := &Registrar{}
	fillIfFound(&registrar.CreatedDate, re.CreatedDate, text)
	fillIfFound(&registrar.DomainDNSSEC, re.DomainDNSSEC, text)
	fillIfFound(&registrar.DomainID, re.DomainID, text)
	fillIfFound(&registrar.DomainName, re.DomainName, text)
	fillIfFound(&registrar.DomainStatus, re.DomainStatus, text)
	fillIfFound(&registrar.Emails, re.Emails, text)
	fillIfFound(&registrar.ExpirationDate, re.ExpirationDate, text)
	fillIfFound(&registrar.NameServers, re.NameServers, text)
	fillIfFound(&registrar.ReferralURL, re.ReferralURL, text)
	fillIfFound(&registrar.RegistrarID, re.RegistrarID, text)
	fillIfFound(&registrar.RegistrarName, re.RegistrarName, text)
	fillIfFound(&registrar.UpdatedDate, re.UpdatedDate, text)
	fillIfFound(&registrar.WhoisServer, re.WhoisServer, text)
	if *registrar == (Registrar{}) {
		return nil
	}
	return registrar
}

func parseRegistrant(text *string, re *RegistrantRegex) *Registrant {
	if re == nil {
		return nil
	}

	registrant := &Registrant{}
	fillIfFound(&registrant.ID, re.ID, text)
	fillIfFound(&registrant.Name, re.Name, text)
	fillIfFound(&registrant.Organization, re.Organization, text)
	if re.Address == nil {
		fillIfFound(&registrant.Street, re.Street, text)
		fillIfFound(&registrant.StreetExt, re.StreetExt, text)
		fillIfFound(&registrant.City, re.City, text)
		fillIfFound(&registrant.Province, re.Province, text)
		fillIfFound(&registrant.PostalCode, re.PostalCode, text)
		fillIfFound(&registrant.Country, re.Country, text)
	} else {
		fillGeoAddress(registrant, re.Address, text)
	}
	fillIfFound(&registrant.Phone, re.Phone, text)
	fillIfFound(&registrant.PhoneExt, re.PhoneExt, text)
	fillIfFound(&registrant.Fax, re.Fax, text)
	fillIfFound(&registrant.FaxExt, re.FaxExt, text)
	fillIfFound(&registrant.Email, re.Email, text)
	if *registrant == (Registrant{}) {
		return nil
	}
	return registrant
}

func fillGeoAddress(registrant *Registrant, re *regexp.Regexp, text *string) {
	if re != nil {
		regexMatches := re.FindStringSubmatch(*text)
		resultMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && name != "" {
				resultMap[name] = regexMatches[i]
			}
		}
		registrant.Street = resultMap["street"]
		registrant.City = resultMap["city"]
		registrant.PostalCode = resultMap["postalCode"]
		registrant.StreetExt = resultMap["streetExt"]
		registrant.Province = resultMap["province"]
		registrant.Country = resultMap["country"]
	}
}

// Parse parses whois text for specified domain. Domain is required here to be able to choose specific parser
func Parse(domain string, text string) *Record {
	return parserFor(domain).Parse(text)
}

func parserFor(domain string) IParser {
	for zone, parser := range parsers {
		if strings.HasSuffix(domain, zone) {
			return parser
		}
	}
	return &DefaultParser
}

func fillIfFound(field *string, re *regexp.Regexp, text *string) {
	if re != nil {
		if val, found := findAndJoinStrings(text, re); found {
			*field = val
		}
	}
}

func findAndJoinStrings(text *string, re *regexp.Regexp) (string, bool) {
	if re == nil {
		return "", false
	}

	var keys []string
	var values = make(map[string]struct{})

	for _, res := range re.FindAllStringSubmatch(*text, -1) {
		values[res[1]] = struct{}{}
	}

	for k := range values {
		keys = append(keys, k)
	}

	if len(keys) == 0 {
		return "", false
	}

	return strings.Join(keys[:], ","), true
}

var parsers = map[string]*Parser{}

// RegisterParser is used to register parsers in catalog which is used to select parser for specific domain
func RegisterParser(zone string, parser *Parser) {
	parsers[zone] = parser
}

// DefaultParser is used in case if no parser for TLD not found
var DefaultParser = Parser{
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`^No match for domain "`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`^No match for "`),
	},
	registrarRegex: &RegistrarRegex{
		CreatedDate:    regexp.MustCompile(`(?i)Creation Date: +(.+)`),
		DomainDNSSEC:   regexp.MustCompile(`(?i)dnssec: +([\S]+)`),
		DomainID:       regexp.MustCompile(`(?i)Registry Domain ID: +(.+)`),
		DomainName:     regexp.MustCompile(`(?i)Domain Name: +(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)Status: +(\w+).*`),
		Emails:         regexp.MustCompile(`(?i)Registrar Abuse Contact Email: +(` + EmailRegex + `)`),
		ExpirationDate: regexp.MustCompile(`(?i)Expir\w+ Date: +(.+)`),
		NameServers:    regexp.MustCompile(`(?i)Name Server: +(.+)`),
		ReferralURL:    regexp.MustCompile(`(?i)Referral URL: +(.+)`),
		RegistrarID:    regexp.MustCompile(`(?i)Registrar IANA ID: +(.+)`),
		RegistrarName:  regexp.MustCompile(`(?i)Registrar: +(.+)`),
		UpdatedDate:    regexp.MustCompile(`(?i)Updated Date: +(.+)`),
		WhoisServer:    regexp.MustCompile(`(?i)Whois Server: +(.+)`),
	},
	registrantRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`(?i)Registry Registrant ID: +(.+)`),
		Name:         regexp.MustCompile(`(?i)Registrant Name: +(.+)`),
		Organization: regexp.MustCompile(`(?i)Registrant\s*Organization: +(.+)`),
		Street:       regexp.MustCompile(`(?i)Registrant Street: +(.+)`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`(?i)Registrant City: +(.+)`),
		Province:     regexp.MustCompile(`(?i)Registrant State/Province: +(.+)`),
		PostalCode:   regexp.MustCompile(`(?i)Registrant Postal Code: +(.+)`),
		Country:      regexp.MustCompile(`(?i)Registrant Country: +(.+)`),
		Phone:        regexp.MustCompile(`(?i)Registrant Phone: +(.+)`),
		PhoneExt:     regexp.MustCompile(`(?i)Registrant Phone Ext: +(.+)`),
		Fax:          regexp.MustCompile(`(?i)Registrant Fax: +(.+)`),
		FaxExt:       regexp.MustCompile(`(?i)Registrant Fax Ext: +(.+)`),
		Email:        regexp.MustCompile(`(?i)Registrant Email: +(.+)`),
	},
	adminRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`(?i)Registry Admin ID: +(.+)`),
		Name:         regexp.MustCompile(`(?i)Admin Name: +(.+)`),
		Organization: regexp.MustCompile(`(?i)Admin\s*Organization: +(.+)`),
		Street:       regexp.MustCompile(`(?i)Admin Street: +(.+)`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`(?i)Admin City: +(.+)`),
		Province:     regexp.MustCompile(`(?i)Admin State/Province: +(.+)`),
		PostalCode:   regexp.MustCompile(`(?i)Admin Postal Code: +(.+)`),
		Country:      regexp.MustCompile(`(?i)Admin Country: +(.+)`),
		Phone:        regexp.MustCompile(`(?i)Admin Phone: +(.+)`),
		PhoneExt:     regexp.MustCompile(`(?i)Admin Phone Ext: +(.+)`),
		Fax:          regexp.MustCompile(`(?i)Admin Fax: +(.+)`),
		FaxExt:       regexp.MustCompile(`(?i)Admin Fax Ext: +(.+)`),
		Email:        regexp.MustCompile(`(?i)Admin Email: +(.+)`),
	},
	techRegex: &RegistrantRegex{
		ID:           regexp.MustCompile(`(?i)Registry Tech ID: +(.+)`),
		Name:         regexp.MustCompile(`(?i)Tech Name: +(.+)`),
		Organization: regexp.MustCompile(`(?i)Tech\s*Organization: +(.+)`),
		Street:       regexp.MustCompile(`(?i)Tech Street: +(.+)`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`(?i)Tech City: +(.+)`),
		Province:     regexp.MustCompile(`(?i)Tech State/Province: +(.+)`),
		PostalCode:   regexp.MustCompile(`(?i)Tech Postal Code: +(.+)`),
		Country:      regexp.MustCompile(`(?i)Tech Country: +(.+)`),
		Phone:        regexp.MustCompile(`(?i)Tech Phone: +(.+)`),
		PhoneExt:     regexp.MustCompile(`(?i)Tech Phone Ext: +(.+)`),
		Fax:          regexp.MustCompile(`(?i)Tech Fax: +(.+)`),
		FaxExt:       regexp.MustCompile(`(?i)Tech Fax Ext: +(.+)`),
		Email:        regexp.MustCompile(`(?i)Tech Email: +(.+)`),
	},
}
