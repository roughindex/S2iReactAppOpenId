#! /bin/bash
function remove_file (){
if [ -f "$1" ]; then
    echo "$1 exists removing file"
    rm $1
fi
}

#Downloading latest lua files removing old files if the exist
remove_file ./http.lua
wget https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http.lua  && \
remove_file ./http_headers.lua
wget https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_headers.lua && \
remove_file ./http_connect.lua
wget https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_connect.lua && \
remove_file ./rsa.lua
wget https://raw.githubusercontent.com/spacewander/lua-resty-rsa/master/lib/resty/rsa.lua
