package rsa_test

import (
	"encrypt-tools/rsa"

	"testing"
)

var (
	pubPEM           = "./rsa_public_key.pem"
	privPEM          = "./rsa_private_key_pkcs8.pem"
	thirdPartyPubPEM = "./rsa_public_key.pem"

	temp   = ""
	newrsa *rsa.Keys
)

func init() {
	rsa.Init(pubPEM, privPEM, thirdPartyPubPEM)
	newrsa = rsa.GetRSA()
}

func TestRSAEncrypt(t *testing.T) {
	t.Log("=========开始加密测试==========")
	var err error
	temp, err = newrsa.PublicEncrypt("你要加密的内容")
	// tmp2, err := newrsa.PrivateDecrypt(tmp)
	t.Log(temp, err)
}

func TestRSADecrypt(t *testing.T) {
	t.Log("=========开始解密测试==========")
	var err error
	tmp2, err := newrsa.PrivateDecrypt("W4dv5OZ53R/VP9zjfilvJBF+3nqUuriNN168Zmjh04XgSxUn8X0hB0cw3Dk02x9R4vW3RH9s/owTDRJSp/H6q/xkxf8zsnhScoNluxSCd4ijHd5E7fGluawNDvfXEV32srNvNGtwjxXn6t+M0b73Vm43v7EzLho4NlTWqyiweBuq3BQ5fp6t37aBcXWQqgkjxRqpkXZXSvBW2qgcI47EN3nvZ13Sp/g/tN8hJTwHbuXEkvs5xHvp27nA8bPZzz0WxYwFWyA+Im2NMQLg82FBoJiu9ZvFF8zb860MYkdAh57DdM+HMjG2G7OQVv4Cp/0oK9ziKhFU4M8HqR4nHnBoJg")
	t.Log(tmp2, err)
}
