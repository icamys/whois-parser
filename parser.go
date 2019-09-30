package whoisparser

import (
	"regexp"
	"strings"
)

// Parser structure with registrar and registrant sections
type Parser struct {
	lineMinLen      int
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

	text = p.removeShortLines(text)

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

// removeShortLines trims spaces and removes too short lines
func (p *Parser) removeShortLines(text string) string {
	var line string

	textLines := strings.Split(text, "\n")
	newLines := make([]string, 0, len(textLines))

	for i := 0; i < len(textLines); i++ {
		line = strings.TrimSpace(textLines[i])

		if len(line) < p.lineMinLen {
			continue
		}

		newLines = append(newLines, line)
	}

	return strings.Join(newLines[:], "\n")
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
	fillIfFound(&registrant.Street, re.Street, text)
	fillIfFound(&registrant.StreetExt, re.StreetExt, text)
	fillIfFound(&registrant.City, re.City, text)
	fillIfFound(&registrant.Province, re.Province, text)
	fillIfFound(&registrant.PostalCode, re.PostalCode, text)
	fillIfFound(&registrant.Country, re.Country, text)
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
	lineMinLen: 5,
	errorRegex: &ParseErrorRegex{
		NoSuchDomain:     regexp.MustCompile(`^No match for domain "`),
		RateLimit:        nil,
		MalformedRequest: regexp.MustCompile(`^No match for "`),
	},
	registrarRegex: &RegistrarRegex{
		CreatedDate:    nil, //TODO WHy not `(?i)Creation Date: *(.+)`
		DomainDNSSEC:   regexp.MustCompile(`(?i)dnssec: *([\S]+)`),
		DomainID:       nil, //TODO WHy not `(?i)Registry Domain ID: *(.+)`
		DomainName:     regexp.MustCompile(`(?i)Domain Name: *(.+)`),
		DomainStatus:   regexp.MustCompile(`(?i)Status: *(\w+).*`),
		Emails:         regexp.MustCompile(`(?i)Registrar Abuse Contact Email: *(` + EmailRegex + `)`),
		ExpirationDate: regexp.MustCompile(`(?i)Expir\w+ Date: *(.+)`),
		NameServers:    regexp.MustCompile(`(?i)Name Server: *(.+)`),
		ReferralURL:    regexp.MustCompile(`(?i)Referral URL: *(.+)`),
		RegistrarID:    nil, //TODO WHy not `(?i)Registrar IANA ID: *(.+)`
		RegistrarName:  regexp.MustCompile(`(?i)Registrar: *(.+)`),
		UpdatedDate:    nil, //TODO WHy not `(?i)Updated Date: *(.+)`
		WhoisServer:    regexp.MustCompile(`(?i)Whois Server: *(.+)`),
	},
	registrantRegex: &RegistrantRegex{
		ID:           nil,
		Name:         regexp.MustCompile(`(?i)Registrant Name: *(.+)`),
		Organization: regexp.MustCompile(`(?i)Registrant\s*Organization: *(.+)`),
		Street:       regexp.MustCompile(`(?i)Registrant Street: *(.+)`),
		StreetExt:    nil,
		City:         regexp.MustCompile(`(?i)Registrant City: *(.+)`),
		Province:     nil,
		PostalCode:   regexp.MustCompile(`(?i)Registrant Postal Code: *(.+)`),
		Country:      regexp.MustCompile(`(?i)Registrant Country: *(.+)`),
		Phone:        nil,
		PhoneExt:     nil,
		Fax:          nil,
		FaxExt:       nil,
		Email:        nil,
	},
}
