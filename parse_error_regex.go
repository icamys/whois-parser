package whoisparser

import "regexp"

// ParseErrorRegex contains regular expressions for different kinds of errors
type ParseErrorRegex struct {
	NoSuchDomain     *regexp.Regexp
	RateLimit        *regexp.Regexp
	MalformedRequest *regexp.Regexp
}
