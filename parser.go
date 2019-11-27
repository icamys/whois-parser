package whoisparser

import (
	"regexp"
	"strings"
)

// Parser represents a structure with regular expressions for specific whois sections
type Parser struct {
	errorRegex      *ParseErrorRegex
	registrarRegex  *RegistrarRegex
	registrantRegex *RegistrantRegex
	adminRegex      *RegistrantRegex
	techRegex       *RegistrantRegex
	billRegex       *RegistrantRegex
	skipWordList    []string
}

// Parse parses whois text
func (p *Parser) Parse(text string) *Record {
	record := &Record{
		ErrCode: p.getErrCode(text),
	}

	if record.ErrCode != ErrCodeNoError {
		return record
	}

	record.Registrar = parseRegistrar(&text, p.registrarRegex, p.skipWordList)
	record.Registrant = parseRegistrant(&text, p.registrantRegex, p.skipWordList)
	record.Admin = parseRegistrant(&text, p.adminRegex, p.skipWordList)
	record.Tech = parseRegistrant(&text, p.techRegex, p.skipWordList)
	record.Bill = parseRegistrant(&text, p.billRegex, p.skipWordList)

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

func parseRegistrar(text *string, re *RegistrarRegex, skipWordList []string) *Registrar {
	if re == nil {
		return nil
	}

	registrar := &Registrar{}
	fillIfFound(&registrar.CreatedDate, re.CreatedDate, text, skipWordList)
	fillIfFound(&registrar.DomainDNSSEC, re.DomainDNSSEC, text, skipWordList)
	fillIfFound(&registrar.DomainID, re.DomainID, text, skipWordList)
	fillIfFound(&registrar.DomainName, re.DomainName, text, skipWordList)
	fillIfFound(&registrar.DomainStatus, re.DomainStatus, text, skipWordList)
	fillIfFound(&registrar.Emails, re.Emails, text, skipWordList)
	fillIfFound(&registrar.ExpirationDate, re.ExpirationDate, text, skipWordList)
	fillIfFound(&registrar.NameServers, re.NameServers, text, skipWordList)
	fillIfFound(&registrar.ReferralURL, re.ReferralURL, text, skipWordList)
	fillIfFound(&registrar.RegistrarID, re.RegistrarID, text, skipWordList)
	fillIfFound(&registrar.RegistrarName, re.RegistrarName, text, skipWordList)
	fillIfFound(&registrar.UpdatedDate, re.UpdatedDate, text, skipWordList)
	fillIfFound(&registrar.WhoisServer, re.WhoisServer, text, skipWordList)
	if *registrar == (Registrar{}) {
		return nil
	}
	return registrar
}

func parseRegistrant(text *string, re *RegistrantRegex, skipWordList []string) *Registrant {
	if re == nil {
		return nil
	}

	registrant := &Registrant{}
	fillIfFound(&registrant.ID, re.ID, text, skipWordList)
	fillIfFound(&registrant.Name, re.Name, text, skipWordList)
	fillIfFound(&registrant.Organization, re.Organization, text, skipWordList)
	if re.Address == nil {
		fillIfFound(&registrant.Street, re.Street, text, skipWordList)
		fillIfFound(&registrant.StreetExt, re.StreetExt, text, skipWordList)
		fillIfFound(&registrant.City, re.City, text, skipWordList)
		fillIfFound(&registrant.Province, re.Province, text, skipWordList)
		fillIfFound(&registrant.PostalCode, re.PostalCode, text, skipWordList)
		fillIfFound(&registrant.Country, re.Country, text, skipWordList)
	} else {
		fillGeoAddress(registrant, re.Address, text, skipWordList)
	}
	fillIfFound(&registrant.Phone, re.Phone, text, skipWordList)
	fillIfFound(&registrant.PhoneExt, re.PhoneExt, text, skipWordList)
	fillIfFound(&registrant.Fax, re.Fax, text, skipWordList)
	fillIfFound(&registrant.FaxExt, re.FaxExt, text, skipWordList)
	fillIfFound(&registrant.Email, re.Email, text, skipWordList)
	if *registrant == (Registrant{}) {
		return nil
	}
	return registrant
}

func fillGeoAddress(registrant *Registrant, re *regexp.Regexp, text *string, skipWordList []string) {
	if re != nil {
		regexMatches := re.FindStringSubmatch(*text)
		resultMap := make(map[string]string)
		for i, name := range re.SubexpNames() {
			if i != 0 && name != "" {
				ok := true

				for _, word := range skipWordList {
					if word == regexMatches[i] {
						ok = false
					}
				}

				if ok {
					resultMap[name] = regexMatches[i]
				}

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

// Parse parses whois text for specified domain.
// Domain is used to identify the domain zone and
// to choose the parser should be used for this zone
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

func fillIfFound(field *string, re *regexp.Regexp, text *string, skipWordList []string) {
	if re != nil {
		if val, found := findAndJoinStrings(text, re); found {
			ok := true

			for _, word := range skipWordList {
				if word == val {
					ok = false
				}
			}

			if ok {
				*field = val
			}
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

// DefaultParser is used in case if no parser for TLD is found
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
