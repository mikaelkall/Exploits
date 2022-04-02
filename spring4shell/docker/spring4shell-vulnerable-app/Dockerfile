FROM adoptopenjdk/maven-openjdk11:latest AS builder
COPY --chown=root:root . /home/maven/src
WORKDIR /home/maven/src
RUN mvn clean package

FROM tomcat:9-jdk11-openjdk
EXPOSE 8000
COPY --from=builder /home/maven/src/target/spring4shell.war /usr/local/tomcat/webapps/

#> This also required for setup remote debugging.
#COPY --chown=root:root ./setenv.sh /usr/local/tomcat/bin/setenv.sh

COPY --chown=root:root ./server.xml /usr/local/tomcat/conf/server.xml
RUN apt-get -y update && apt-get -y install python
CMD ["catalina.sh", "run"]

#> For attach visual-studio code and debug other object chains.
#CMD ["catalina.sh", "jpda", "run"]
