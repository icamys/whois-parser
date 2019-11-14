package whoisparser

// Record is a structure that contains parsed info for particular whois sections
type Record struct {
	ErrCode    ErrCode     `json:"error_code,omitempty"`
	Registrar  *Registrar  `json:"registrar,omitempty"`
	Registrant *Registrant `json:"registrant,omitempty"`
	Admin      *Registrant `json:"admin,omitempty"`
	Tech       *Registrant `json:"tech,omitempty"`
	Bill       *Registrant `json:"bill,omitempty"`
}
