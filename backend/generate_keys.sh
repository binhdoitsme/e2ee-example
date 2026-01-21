# 1. Generate private key (PKCS#8 format for Web Crypto)
openssl genpkey -algorithm RSA -out rsa_private_v1.pem -pkeyopt rsa_keygen_bits:4096

# 2. Extract public key (SPKI format for Web Crypto)
openssl pkey -in rsa_private_v1.pem -pubout -out rsa_public_v1.pem

# 3. Verify (optional)
openssl pkey -in rsa_private_v1.pem -text -noout
openssl pkey -pubin -in rsa_public_v1.pem -text -noout