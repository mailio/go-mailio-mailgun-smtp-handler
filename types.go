package mailgunsmtphandler

type Domains struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		CreatedAt string `json:"created_at"`
		ID        string `json:"id"`
		Name      string `json:"name"`
		State     string `json:"state"`
		WebPrefix string `json:"web_prefix"`
		Type      string `json:"type"`
		Disabled  struct {
			Code        string `json:"code"`
			Note        string `json:"note"`
			Permanently bool   `json:"permanently"`
			Reason      string `json:"reason"`
		} `json:"disabled"`
	} `json:"items"`
}
