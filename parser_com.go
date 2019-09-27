package whoisparser

var comParser = DefaultParser

func init() {
	RegisterParser(".com", &comParser)
}
