FROM tomcat:8.0
EXPOSE 8080

RUN apt-get update -y && apt-get install -y --no-install-recommends \
   python \
   && rm -rf /var/lib/apt/lists/*

COPY tomcat-users.xml /usr/local/tomcat/conf/
COPY context.xml /usr/local/tomcat/webapps/manager/META-INF/
