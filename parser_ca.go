package whoisparser

var caParser = DefaultParser

func init() {
	RegisterParser(".ca", &caParser)
}
