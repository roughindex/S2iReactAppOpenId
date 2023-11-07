local function noauth(uri)
    local allow = {"/favicon", "/callback"}
    for i=1, #allow do
        if uri == allow[i] then
            return true
        end
    end

    -- disallow dotpaths
    if string.match(uri, "%.%.") then
        return false
    end

    cacheable = "/static/"
    return not uri:sub(1, #cacheable) ~= cacheable
end

local permittedRole = os.getenv("PERMITTED_ROLE")
local rolesClaim = os.getenv("ROLES_CLAIM")
local usernameClaim = os.getenv("USERNAME_CLAIM")

local function checkAccess(claims)
    roles = claims[rolesClaim]
    user = claims[usernameClaim]
    rType = type(roles)
    if rType == "string" then
        if roles == permittedRole then
            ngx.var.userid = user
            return nil
        else
            ngx.log(ngx.WARN, "Denying access to user " .. user .. " with role " .. roles)
        end
    elseif rType == "table" then
        for _, role in pairs(roles) do
            if role == permittedRole then
                ngx.var.userid = user
                return nil
            else
                ngx.log(ngx.WARN, "Denying access to user " .. user .. " with roles " .. roles)
            end
        end
    else
        ngx.log(ngx.WARN, "Unable to authenticate user " .. user .. ", type of roles: " .. rType)
    end
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

if noauth(ngx.var.uri) then 
    ngx.log(ngx.DEBUG, "skipping authentication for uri " .. ngx.var.uri)
else
    local oid = require("resty.openid")
    checkAccess(oid.getClaims())
    ngx.log(ngx.DEBUG, "access granted to user " .. ngx.var.userid .. " for uri " .. ngx.var.uri)
end