package whoisparser

var meParser = DefaultParser

func init() {
	RegisterParser(".me", &meParser)
}
