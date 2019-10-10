package whoisparser

var infoParser = DefaultParser

func init() {
	RegisterParser(".info", &infoParser)
}
