package core

type Authorize struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
}
