package whoisparser

var ioParser = DefaultParser

func init() {
	RegisterParser(".io", &ioParser)
}
