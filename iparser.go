package whoisparser

// IParser interface for parser extension
type IParser interface {
	Parse(string) *Record
}
