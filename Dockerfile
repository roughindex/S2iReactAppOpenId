ARG NODE_VERSION=18.12.0
ARG MODE

FROM node:${NODE_VERSION}-alpine as ui

WORKDIR /app/src
COPY ./package.json ./

RUN npm install

COPY ./ui/src ./src/

RUN npm run build
  
FROM scratch as build-nginx
# Each COPY creates a layer. Each layer has an overhead, so build the whole structure 
# we want here, then copy it all in one go into a single layer the final image

COPY certs /etc/nginx/certs
COPY auth.lua /

COPY conf/*.conf /usr/local/openresty/nginx/conf/
COPY static/ /usr/local/openresty/nginx/html/static/

COPY --from=ui /app/src/build /usr/local/openresty/nginx/html
COPY start.sh /
COPY http.lua http_connect.lua http_headers.lua openid.lua rsa.lua /usr/local/openresty/lualib/resty/
COPY callback.lua /usr/local/openresty/nginx/

FROM openresty/openresty:1.21.4.1-8-alpine-apk
COPY --from=build-nginx / /

# These parameters are set in the docker-compose.yml
ARG RESOLVER
ENV RESOLVER=${RESOLVER}
ARG AUTHORIZATION_PARAMS
ARG REDIRECT_URI
ARG LOGOUT_PATH
ARG DISCOVERY
ARG CLIENT_ID
ARG CLIENT_SECRET
ARG SSL_VERIFY
ARG SCOPE
ARG USER_ID
ARG XREALIP
ARG XFORWARDEDPROTO
ARG BACKENDHOST
ARG BACKENDPORT
ARG DNS
ARG ACCESS_CONTROL_ALLOW_ORIGIN

COPY openid-configuration OAuth2PublicKey.pem /etc/nginx/

VOLUME /var/log/nginx

CMD ["/bin/sh", "start.sh"]

STOPSIGNAL SIGQUIT
