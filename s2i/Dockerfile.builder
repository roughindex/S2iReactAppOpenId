FROM alpine:latest

RUN apk add --update --no-cache nodejs npm

COPY assemble save-artefacts run /app/

LABEL io.openshift.s2i.scripts-url="image:///app"
