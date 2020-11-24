FROM alpine:latest
RUN apk update
RUN apk add bash
COPY exploit.sh /exploit.sh
RUN chmod +x /exploit.sh
CMD ["tail", "-f", "/dev/null"]
