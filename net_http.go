package main

import (
	"fmt"
	"net/http"
	"strings"
)

type NetHttpBruteImpl struct {
	method             string
	url                string
	username           string
	expectedStatusCode int
	headers            map[string]string
}

func NewNetHttpBruteImpl(method string, url string, username string, expectedStatusCode int, headers map[string]string) *NetHttpBruteImpl {
	return &NetHttpBruteImpl{
		method:             strings.ToUpper(method),
		url:                url,
		username:           username,
		expectedStatusCode: expectedStatusCode,
		headers:            headers,
	}
}

func (c *NetHttpBruteImpl) Do(password string) (bool, error) {
	payload := fmt.Sprintf("username=%s&password=%s", c.username, password)
	req, err := http.NewRequest(c.method, c.url, strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	// req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// const hash_value = "hash" // hash value of the next action
	// req.Header.Set("Next-Action", hash_value)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == c.expectedStatusCode, nil
}
