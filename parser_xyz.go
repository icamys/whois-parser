package whoisparser

var xyzParser = DefaultParser

func init() {
	RegisterParser(".xyz", &xyzParser)
}
