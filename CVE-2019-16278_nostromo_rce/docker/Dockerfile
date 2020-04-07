FROM debian:latest

EXPOSE 8080
COPY nostromo-1.9.6 /var/nostromo
WORKDIR /var/nostromo

RUN apt-get -y update
RUN apt-get -y install build-essential libssl-dev groff bash
#RUN mkdir -p /usr/local/sbin
#RUN mkdir -p /usr/share/man/man8
#RUN mkdir -p /var/nostromo


#RUN make && make install 2>/dev/null
#ENTRYPOINT ["tail", "-f", "/dev/null"]
