#生成私钥
openssl genrsa -out rsa_private_key.pem 2048
#私钥转换成PKCS8格式
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem
#生成公钥
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem