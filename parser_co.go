package whoisparser

var coParser = DefaultParser

func init() {
	RegisterParser(".co", &coParser)
}
