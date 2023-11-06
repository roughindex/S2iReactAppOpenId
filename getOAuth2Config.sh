#! /bin/bash
function remove_file (){
if [ -f "$1" ]; then
    echo "$1 exists removing file"
    rm $1
fi
}

remove_file ./openid-configuration
. .env
cd volume
wget --no-check-certificate https://${OAUTH2_DOMAIN}/.well-known/openid-configuration
wget --no-check-certificate -O jwks.json `jq -r ".jwks_uri" openid-configuration`
jq -r ".keys[0].x5c[0]" jwks.json | tr -d "\n" | base64 -d -w0 > publicKey.der
openssl x509 -inform der -in publicKey.der -pubkey > publicKey.pem
cd ..
