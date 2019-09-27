package whoisparser

import "regexp"

var coJpParser = jpParser

func init() {
	coJpParser.registrarRegex.CreatedDate = regexp.MustCompile(`\[Registered Date\] *(.+)`)
	coJpParser.registrarRegex.ExpirationDate = regexp.MustCompile(`\[State\] *(.+)`)
	coJpParser.registrarRegex.UpdatedDate = regexp.MustCompile(`\[Last Update\] *(.+)`)

	RegisterParser(".co.jp", coJpParser)
}
