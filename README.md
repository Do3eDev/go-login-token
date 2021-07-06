# go-login-token

```go
package main

import (
	"fmt"
	"github.com/Do3eDev/go-login-token"
	"time"
)

func main() {
	encode, decode, timestamp := go_login_token.GetB64result("shop.myshopify.com", time.Now().UnixNano(), true)
	fmt.Println("encode, decode, timestamp: ", encode, decode, timestamp)

	encode, decode, timestamp = go_login_token.GetB64result(encode, timestamp, false)
	fmt.Println("encode, decode, timestamp: ", encode, decode, timestamp)

	var pass = "Abc@0000"
	var hashPass, err = go_login_token.HashGenerateFromPassword(pass)
	fmt.Println("hashPass, err: ", hashPass, err)

	var baseUrl = "https://domain.com/oauth2callback?abc=test&dev=true"
	var clientSecret = "security_user_secret_key_abcd1234xyz555"
	var user = "admin"

	var loginHmacUrl, err2 = go_login_token.LoginRenderHmacToken(hashPass, pass, user, clientSecret, baseUrl)
	fmt.Println("loginHmacUrl, err2: ", loginHmacUrl, err2)

	var valid = go_login_token.HmacValidate(loginHmacUrl, clientSecret)
	fmt.Println("login status: ", valid)
}
```