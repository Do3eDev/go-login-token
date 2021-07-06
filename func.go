package go_login_token

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const RPNUM = 5
const KETCHECK64 = `qQ1wW2eE3rR4tT5yY6uU7iI8oO9pP0aA1sS2dD3fF4gG5hH6jJ7kK8lL9zZ0xX1cC2vV3bB4nN5mM6qQ1wW2eE3rR4tT5yY6uU7iI8oO9pP0aA1sS2dD3fF4gG5hH6jJ7kK8lL9zZ0xX1cC2vV3bB4nN5mM6qQ1wW2eE3rR4tT5yY6uU7iI8oO9pP0aA1sS2dD3fF4gG5hH6jJ7kK8lL9zZ0xX1cC2vV3bB4nN5mM6qQ1wW2eE3rR4tT5yY6uU7iI8oO9pP0aA1sS2dD3fF4gG5hH6jJ7kK8lL9zZ0xX1cC2vV3bB4nN5mM6`

func GetB64result(dataEnDe string, timestampEncode int64, statusEncode bool) (resultEncode, resultDecode string, timestamp int64) {

	//encode, decode, timestamp := go_login_token.GetB64result("shop.myshopify.com", time.Now().UnixNano(), true)
	//fmt.Println(encode, decode, timestamp)

	//encode, decode, timestamp = go_login_token.GetB64result(encode, timestamp, false)
	//fmt.Println(encode, decode, timestamp)

	var checkDecode bool
	if timestampEncode == 0 {
		return
	}
	resultDecode = dataEnDe
	timestamp = timestampEncode
	if statusEncode == false {
		resultEncode = dataEnDe
		checkDecode = true
	}

	var t1 = timestampEncode
	for t1 >= 10 {
		t1 = getNumberKey(t1)
	}
	var t2 = getNumberKey(timestampEncode)
	var t3 = getNumberKey(t2)

	var b64keyCheck64 = base64.StdEncoding.EncodeToString([]byte(KETCHECK64))
	var sq1 = b64keyCheck64[t1 : t1+RPNUM]
	var sq2 = b64keyCheck64[t2 : t2+RPNUM]
	var sq3 = b64keyCheck64[t1+t3 : t1+t3+RPNUM]
	var sq4 = b64keyCheck64[t1+t2+t3 : t1+t2+t3+RPNUM]
	var sq5 = b64keyCheck64[t2-t1-t3 : t2-t1-t3+RPNUM]
	var sq6 = b64keyCheck64[t2-RPNUM : t2]
	var sq7 = b64keyCheck64[t1+t2+t3-RPNUM : t1+t2+t3]
	var sq8 = b64keyCheck64[t2-t1-t3-RPNUM : t2-t1-t3]
	var sq9 = b64keyCheck64[t2+2*(t1+t3) : t2+2*(t1+t3)+RPNUM]
	var sq10 = b64keyCheck64[t2-2*(t1+t3)-RPNUM : t2-2*(t1+t3)]

	if checkDecode == false {
		var b64Shop = base64.StdEncoding.EncodeToString([]byte(dataEnDe))

		var v1 = base64.StdEncoding.EncodeToString([]byte(b64Shop[:t1]))
		var v2 = base64.StdEncoding.EncodeToString([]byte(b64Shop[t1:t3]))
		var v3 = base64.StdEncoding.EncodeToString([]byte(b64Shop[t3:]))

		rpV1 := strings.Replace(v1, "==", sq2, -1)
		rpV1 = strings.Replace(rpV1, "=", sq1, -1)

		rpV2 := strings.Replace(v2, "==", sq4, -1)
		rpV2 = strings.Replace(rpV2, "=", sq3, -1)

		rpV3 := strings.Replace(v3, "==", sq6, -1)
		rpV3 = strings.Replace(rpV3, "=", sq5, -1)

		rpV4 := strings.Replace(base64.StdEncoding.EncodeToString([]byte(rpV1+sq7+rpV2+sq8+rpV3)), "==", sq10, -1)
		rpV4 = strings.Replace(rpV4, "=", sq9, -1)

		resultEncode = rpV4
	}

	if checkDecode == true {
		rpV4 := strings.Replace(resultEncode, sq10, "==", -1)
		rpV4 = strings.Replace(rpV4, sq9, "=", -1)

		var sv0, err0 = base64.StdEncoding.DecodeString(rpV4)
		if err0 != nil {
			return
		}
		resultEncode1 := string(sv0)

		id7 := strings.Index(resultEncode1, sq7)
		id8 := strings.Index(resultEncode1, sq8)

		if id7 <= 0 || id8 <= 0 {
			return
		}

		rpV1 := strings.Replace(resultEncode1[:id7], sq2, "==", -1)
		rpV1 = strings.Replace(rpV1, sq1, "=", -1)

		rpV2 := strings.Replace(resultEncode1[id7+RPNUM:id8], sq4, "==", -1)
		rpV2 = strings.Replace(rpV2, sq3, "=", -1)

		rpV3 := strings.Replace(resultEncode1[id8+RPNUM:], sq6, "==", -1)
		rpV3 = strings.Replace(rpV3, sq5, "=", -1)

		var sv1, err1 = base64.StdEncoding.DecodeString(rpV1)
		if err1 != nil {
			return
		}
		var sv2, err2 = base64.StdEncoding.DecodeString(rpV2)
		if err2 != nil {
			return
		}
		var sv3, err3 = base64.StdEncoding.DecodeString(rpV3)
		if err3 != nil {
			return
		}

		var sb4, err4 = base64.StdEncoding.DecodeString(string(sv1) + string(sv2) + string(sv3))
		if err4 != nil {
			return
		}
		resultDecode = string(sb4)
	}
	return
}

func getNumberKey(timestamp int64) (rs int64) {
	split := strings.Split(fmt.Sprint(timestamp), "")
	for _, s := range split {
		n1, _ := strconv.Atoi(s)
		rs += int64(n1)
	}
	return
}
