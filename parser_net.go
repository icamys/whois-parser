package whoisparser

var netParser = DefaultParser

func init() {
	RegisterParser(".net", &netParser)
}
