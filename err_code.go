package whoisparser

// ErrCode is a type for parsing error codes
type ErrCode int

const (
	// ErrCodeNoError is returned when no request errors encountered
	ErrCodeNoError ErrCode = 0

	// ErrCodeNoSuchDomain is returned when we've got "no such domain" error
	ErrCodeNoSuchDomain ErrCode = 1

	// ErrCodeRequestRateLimit is returned when the request rate limit reached
	ErrCodeRequestRateLimit ErrCode = 2

	// ErrCodeMalformedRequest is returned when a malformed request sent
	ErrCodeMalformedRequest ErrCode = 3

	// ErrCodeTldHasNoServer is returned when the requested TLD has no whois server
	ErrCodeTldHasNoServer ErrCode = 4

	// ErrCodeEmptyWhois is returned when the whois text is empty
	ErrCodeEmptyWhois ErrCode = 5

	// ErrCodeNoErrorRules is returned when the error checking regular expressions
	// are not set for current parser
	ErrCodeNoErrorRegex ErrCode = 6
)

var (
	errCodeDescription = map[ErrCode]string{
		ErrCodeNoError:          "no errors",
		ErrCodeNoSuchDomain:     "no such domain",
		ErrCodeRequestRateLimit: "request rate limit reached",
		ErrCodeMalformedRequest: "malformed request",
		ErrCodeTldHasNoServer:   "TLD has no server",
		ErrCodeEmptyWhois:       "whois is empty",
	}
)

// GetErrCodeDescription returns error code description
func GetErrCodeDescription(code ErrCode) string {
	return errCodeDescription[code]
}
