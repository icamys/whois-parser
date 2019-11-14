package whoisparser

// IParser is the parser interface
type IParser interface {
	Parse(string) *Record
}
