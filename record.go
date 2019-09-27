package whoisparser

// Record structure with info about registars and registants
type Record struct {
	ErrCode    ErrCode     `json:"error_code,omitempty"`
	Registrar  *Registrar  `json:"registrar,omitempty"`
	Registrant *Registrant `json:"registrant,omitempty"`
	Admin      *Registrant `json:"admin,omitempty"`
	Tech       *Registrant `json:"tech,omitempty"`
	Bill       *Registrant `json:"bill,omitempty"`
}
