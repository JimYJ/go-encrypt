package encrypt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
	"sync"
)

var (
	privateKey, publicKey           []byte
	privateKeyBlock, publicKeyBlock *pem.Block
	once                            sync.Once
)

//配置
const (
	charset      = "UTF-8"
	base64format = "UrlSafeNoPadding"
	keyType      = "PKCS8"
	algorithm    = crypto.SHA1
)

var (
	rsaKeys *Keys
)

var (
	publicPEM           string
	privatePEM          string
	thirdPartyPublicPEM string
)

// Init 初始化证书
func Init(pubPEM, privPEM, thirdPartyPubPEM string) {
	publicPEM = pubPEM
	privatePEM = privPEM
	thirdPartyPublicPEM = thirdPartyPubPEM
}

// Keys 新浪支付证书
type Keys struct {
	publicKey           *rsa.PublicKey
	privateKey          *rsa.PrivateKey
	thirdPartyPublicKey *rsa.PublicKey
}

// GetRSA 获取对象
func GetRSA() *Keys {
	once.Do(newRsaKeys)
	return rsaKeys
}

// newRsaKeys 初始化对象
func newRsaKeys() {
	publicKey, err := ioutil.ReadFile(publicPEM)
	if err != nil {
		log.Panicln(publicPEM, " is cannot open")
	}
	privateKey, err := ioutil.ReadFile(privatePEM)
	if err != nil {
		log.Panicln(privatePEM, " is cannot open")
	}
	thirdPartyPublicKey, err := ioutil.ReadFile(thirdPartyPublicPEM)
	if err != nil {
		log.Panicln(thirdPartyPublicPEM, " is cannot open")
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		log.Panicln("public key error")
		return
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Panicln(err)
		return
	}
	pub := pubInterface.(*rsa.PublicKey)
	block, _ = pem.Decode(privateKey)
	if block == nil {
		log.Panicln("private key error")
		return
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Panicln(err)
		return
	}
	pri, ok := priv.(*rsa.PrivateKey)
	block, _ = pem.Decode(thirdPartyPublicKey)
	if block == nil {
		log.Panicln("sina pay public key error")
		return
	}
	thirdPartyPubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Panicln(err)
		return
	}
	thirdPartyPub := thirdPartyPubInterface.(*rsa.PublicKey)
	if ok {
		rsaKeys = &Keys{
			publicKey:           pub,
			privateKey:          pri,
			thirdPartyPublicKey: thirdPartyPub,
		}
		return
	}
	log.Panicln("private key not supported")
	return
}

// ThirdPubEncrypt 使用第三方公钥加密
func (r *Keys) ThirdPubEncrypt(data string) (string, error) {
	return r.publicEncrypt(data, r.thirdPartyPublicKey)
}

// PublicEncrypt 使用自有公钥加密
func (r *Keys) PublicEncrypt(data string) (string, error) {
	return r.publicEncrypt(data, r.publicKey)
}

// publicEncrypt 使用公钥加密
func (r *Keys) publicEncrypt(data string, publicKey *rsa.PublicKey) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bytes)
	}
	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// PrivateDecrypt 使用自有私钥解密
func (r *Keys) PrivateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}
	return buffer.String(), err
}

// Sign 数据加签(自有私钥)
func (r *Keys) Sign(data string) (string, error) {
	h := algorithm.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, algorithm, hashed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sign), err
}

// Verify 数据验签
func (r *Keys) verify(data string, sign string, publicKey *rsa.PublicKey) error {
	h := algorithm.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		log.Println(err)
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, algorithm, hashed, decodedSign)
}

// Verify 数据验签(自有公钥)
func (r *Keys) Verify(data string, sign string) error {
	return r.verify(data, sign, r.publicKey)
}

// VerifyThird 数据验签(第三方公钥)
func (r *Keys) VerifyThird(data string, sign string) error {
	return r.verify(data, sign, r.thirdPartyPublicKey)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}
