FROM adoptopenjdk/maven-openjdk11:latest AS builder
COPY --chown=root:root . /home/maven/src
WORKDIR /home/maven/src
RUN mvn clean package

FROM tomcat:9-jdk11-openjdk
EXPOSE 8080
COPY --from=builder /home/maven/src/target/spring4shell.war /usr/local/tomcat/webapps/
CMD ["catalina.sh", "run"]
#WORKDIR /usr/local/tomcat
#CMD ["/usr/local/tomcat/bin/catalina.sh","run"]
