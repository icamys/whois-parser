package whoisparser

var onlineParser = DefaultParser

func init() {
	RegisterParser(".online", &onlineParser)
}
