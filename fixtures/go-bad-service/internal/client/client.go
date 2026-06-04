package client

import (
	"net/http"
)

func FetchUser(url string) ([]byte, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func FetchDefault(url string) error {
	resp, _ := http.Get(url)
	_ = resp
	return nil
}

func BadSpacing(){ return }
