local cjson = require("cjson")
local http = require("resty.http")
local ffi = require("ffi")
local ffiCdef = ffi.cdef
local ffiNew = ffi.new
local ffiStr = ffi.string
local ffiTypeof = ffi.typeof
local C = ffi.C

local resty_rsa = require("resty.rsa")

local _M = { _VERSION = '0.1' }
_M._USER_AGENT = "lua-resty-openid/" .. _M._VERSION .. " (Lua) ngx_lua/" .. ngx.config.ngx_lua_version

-- Configuration
_M.scope = "openid"
_M.clientId = os.getenv("OAUTH2_CLIENT_ID")
_M.clientSecret = os.getenv("OAUTH2_CLIENT_SECRET")
_M.callbackUri = os.getenv("OAUTH2_CALLBACK_URI")
_M.defaultExpiry = os.getenv("OAUTH2_DEFAULT_EXPIRY") or 3600
_M.domain = os.getenv("OAUTH2_DOMAIN")
_M.publicKeyFileName = os.getenv("OAUTH2_PK_FILE") or '/etc/nginx/OAuth2PublicKey.pem'

local uint8Array = ffiTypeof "uint8_t[?]"
ffiCdef[[
typedef unsigned char u_char;
u_char * ngx_hex_dump(u_char *dst, const u_char *src, size_t len);
int RAND_bytes(u_char *buf, int num);
]]

function _M.init()
    local publicKeyFile = io.open(_M.publicKeyFileName,'r')
    _M.publicKey=publicKeyFile:read("*all")
    io.close(publicKeyFile)

    local rsa, rsaerr = resty_rsa:new({ public_key = _M.publicKey, algorithm = "SHA256" })
    if rsaerr then error("new rsa err: " .. rsaerr) end
    _M.rsa = rsa

    local configFile = io.open('/etc/nginx/openid-configuration','r')
    local config = cjson.decode(configFile:read("*all"))
    _M.authorizationEndpoint=config.authorization_endpoint
    _M.tokenEndpoint=config.token_endpoint
    io.close(configFile)
end

function random(_)
    local len = 16
    local arr = ffiNew(uint8Array, len)
    C.RAND_bytes(arr, len)
    if not arr then return nil end

    local hex = ffiNew(uint8Array, len * 2)
    C.ngx_hex_dump(hex, arr, len)
    return ffiStr(hex, len * 2), true
end

function decode(str) return cjson.decode(ngx.decode_base64(str)) end
function _M.verifiedClaims(jwtString)
    assert(jwtString, "Cannot validate a nil JWT")
    assert(_M.publicKey, "Cannot validate against a nil public key")

    local headerString, claimsString, signature = string.match(jwtString, "^(.+)%.(.+)%.(.+)$")
    local header, message, padding = decode(headerString), headerString.."."..claimsString, (#signature % 4)==0 and 0 or (4 - (#signature % 4))

    assert(header.alg=="RS256", "Alogorithm not supported: "..header.alg)

    local decodedSignature = ngx.decode_base64(signature:gsub("-", "+"):gsub("_", "/")..string.rep("=", padding))
    assert(decodedSignature, "Cannot validate a nil decoded signature: "..signature)

    local verified, err = _M.rsa:verify(message, decodedSignature)
    if err then error("Failed to verify JWT "..err) end
    if not verified then error("JWT failed verification") end
    
    return decode(claimsString)
end

function _M.expired(jwtString)
    assert(jwtString, "Cannot retrieve claims from a nil JWT")
    -- the claims are the second part of the message, after a period "." and 
    -- until the next period encoded and serialised as base64 and JSON
    local i = string.find(jwtString, "%.") + 1
    local j = string.find(jwtString, "%.", i) - 1
    local claims = decode(string.sub(jwtString, i, j))

    assert(claims.exp, "Claim missing the 'exp' field")
    return claims.exp < os.time()
end

function _M.callback()
    local qs = ngx.var.query_string
    preventCSRF(qs)

    local tokenRequestParams = getTokenRequestParams(qs)
    local tokenResponse, err = getToken(tokenRequestParams)

    if not tokenResponse then -- The http call failed (network, DNS etc)
        exit(500, "Failed to call ".._M.tokenEndpoint.." error: "..err)
    elseif tokenResponse.status ~= 200 then -- The http call was made but the server issued an error
        message = "Call to ".._M.tokenEndpoint.." returned error: "..tostring(tokenResponse.status)..": "..
            tokenResponse.reason.." The detailed error message will only appear on the authentication servers"
        exit(tokenResponse.status, message)
    else
        -- Success
        ngx.log(ngx.INFO, "Authentication success to ".._M.tokenEndpoint)
        local resumeuri = ngx.var.cookie_resumeuri
        setCookies(tokenResponse)
        if resumeuri then
            ngx.redirect(resumeuri)
        else
            ngx.redirect("/")
        end
    end
end

function _M.getClaims()
    local jwtString = ngx.var.cookie_xjwttoken
    if jwtString then -- Validate the jwt
        if _M.expired(jwtString) then -- check if the refresh token exists and has not expired
            ngx.log(ngx.ERR, "token expired")
            ngx.header.set_cookie = "xjwttoken=; Path=/; Secure; Expires=Thu, Jan 01 1970 00:00:00 UTC;"
            loginRedirect()
        else
            local claims, err = _M.verifiedClaims(jwtString)
            if err then
                exit(403, "Token validation failed: "..err)
            else
                return claims
            end
        end
    else
        loginRedirect()
    end
end

function loginRedirect()
    -- No JWT so redirect to authentication server and request Authorization
    -- https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.1 
    ngx.header["Cache-Control"] = "no-cache, no-store, max-age=0"
    local state, uri, sixtySecondExpiry =  random(), ngx.var.request_uri, ngx.cookie_time(ngx.time() + 60)

    local resumeuri, params = ngx.var.query_string and uri.."?"..ngx.var.query_string or uri, {
        client_id = _M.clientId, 
        scope = _M.scope, 
        redirect_uri = ngx.var.scheme.."://"..ngx.var.http_host.._M.callbackUri, 
        response_type = 'code',
        state = state}

    ngx.header.set_cookie = { "state=" .. state .. "; Path=/; Secure; HttpOnly; Expires=" .. sixtySecondExpiry,
                              "resumeuri=" .. resumeuri .. "; Path=/; Secure; HttpOnly; Expires=" .. sixtySecondExpiry}
    -- TODO: Allow deep links other than GET

    ngx.redirect(_M.authorizationEndpoint .. "?" .. ngx.encode_args(params))
end

function get(qs, field)
    local i = string.find(qs, field.."=")
    local j = string.find(qs, "&", i) or string.len(qs) + 1
    return string.sub(qs, i+1+string.len(field), j - 1)
end

function exit(status, message)
    ngx.log(ngx.ERR, message)
    ngx.exit(status)
end

function preventCSRF(qs)
    -- This prevents CSRF attack because the adversary would not be able to read the 
    -- secure HTTP_ONLY cookie and cannot construct a valid query string as result.
    local state = get(qs, "state")

    if ngx.var.cookie_state ~= state then exit(403, "Invalid state detected") end
end

function getTokenRequestParams(qs)
    -- Call the authorization server for a Token Request https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.3.1
    -- with the code received from the browser received from an Authentication Response
    -- https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.5

    return ngx.encode_args({
        grant_type = "authorization_code",
        client_id = _M.clientId,
        client_secret = _M.clientSecret,
        code = get(qs, "code"),
        redirect_uri = ngx.var.scheme.."://"..ngx.var.http_host.._M.callbackUri 
    })
end    

function getHeaders(body)
    return {["content-length"] = string.len(body),
            ["content-type"] = "application/x-www-form-urlencoded" }
end

function getToken(body)
    return http.request_uri(http.new() or {}, 
        _M.tokenEndpoint, {
            method = "POST",
            body = body,
            headers = getHeaders(body),
            ssl_verify = false,
            keepalive = false
        })
end

function setCookies(tokenResponse)
    local tokens = cjson.decode(tokenResponse.body)
    local expiresIn = tokens["expires_in"] or 3600 -- TODO replace magic number with config
    local expiry = ngx.time() + expiresIn
    -- State is used for CORS protection

    local jwt = "xjwttoken=" .. tokens["id_token"] .. "; Path=/; Secure; Expires=" .. ngx.cookie_time(expiry)
    local cookies = { jwt, 
                     "state=; Path=/; Secure; HttpOnly; max-age=-1",
                     "resumeuri=; Path=/; Secure; HttpOnly; max-age=-1"}
                     
    if tokens["refresh_token"] then
        local expires = ngx.cookie_time(tokens["refresh_token_expires_in"] or 3600)
        table.insert(cookies, "refresh=" .. tokens["refresh_token"] .. "; Path=/; Secure; HttpOnly; Expires=" .. expires)
    end

    ngx.header["Set-Cookie"] = cookies
end

return _M
