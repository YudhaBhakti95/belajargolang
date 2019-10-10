package model

type user struct {
	Username  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Password  string `json:"password"`
	Token     string `json:"token"`
}

type responseresult struct {
	Error  string `json:"error"`
	Result string `json:"result"`
}
