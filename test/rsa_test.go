package rsa_test

import (
	"encrypt-tools/encrypt"

	"testing"
)

var (
	pubPEM           = "./rsa_public_key.pem"
	privPEM          = "./rsa_private_key_pkcs8.pem"
	thirdPartyPubPEM = "./rsa_public_key.pem"

	temp   = ""
	sign   = ""
	newrsa *encrypt.Keys
)

func init() {
	encrypt.Init(pubPEM, privPEM, thirdPartyPubPEM)
	newrsa = encrypt.GetRSA()
}

func TestRSAEncrypt(t *testing.T) {
	t.Log("=========Start Encrypt Test==========")
	var err error
	temp, err = newrsa.PublicEncrypt("你要加密的内容")
	// tmp2, err := newrsa.PrivateDecrypt(tmp)
	t.Log(temp, err)
}

func TestRSADecrypt(t *testing.T) {
	t.Log("=========Start Decrypt Test==========")
	var err error
	tmp2, err := newrsa.PrivateDecrypt(temp)
	t.Log(tmp2, err)
}

func TestRSASignVerify(t *testing.T) {
	t.Log("=========Start Sign & Verify Test==========")
	var err error
	unSgin := "aaaaa=1"
	sign, err := newrsa.Sign(unSgin)
	t.Log(sign, err)
	err = newrsa.Verify(unSgin, sign)
	t.Log(err)
}
