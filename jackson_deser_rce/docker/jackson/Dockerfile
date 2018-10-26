FROM maven:3-jdk-7 AS builder

COPY ./ /usr/src/
WORKDIR /usr/src

RUN cd /usr/src; \
    mvn -U clean package -Dmaven.test.skip=true

FROM vulhub/java:7u21-jdk

RUN apt-get update && apt-get install -y \
     python

COPY --from=builder /usr/src/target/jackson_vuln_server.jar /jackson_vuln_server.jar
EXPOSE 8080
CMD ["java", "-jar", "/jackson_vuln_server.jar"]
