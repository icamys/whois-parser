package whoisparser

var tvParser = DefaultParser

func init() {
	RegisterParser(".tv", &tvParser)
}
