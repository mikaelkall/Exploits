# This is the Dockerfile for JBOSS AS 6.0.0.Final
# 
# IMPORTANT
# ---------
# The resulting image of this Dockerfile DOES NOT contain a JBOSS Domain.
# You will need to create a domain on a new inherited image.
#
# REQUIRED FILES TO BUILD THIS IMAGE
# ----------------------------------
# (1) jdk-6u45-linux-x64.rpm.bin
#     Download from http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javase6-419409.html#jdk-6u45-oth-JPR
# Note: OpenJDK will NOT work and will result into a ClassCastException when running JBOSS

FROM jboss/base:latest
MAINTAINER Olivier Vanekem <olivier.vanekem@gmail.com>

# User root user to install software
USER root

# Install necessary packages
RUN yum -y install wget
RUN yum -y install nmap-ncat
RUN yum clean all

COPY jdk-6u45-linux-x64-rpm.bin /opt/jboss/
RUN chmod 755 /opt/jboss/jdk-6u45-linux-x64-rpm.bin
RUN /opt/jboss/jdk-6u45-linux-x64-rpm.bin && rm /opt/jboss/jdk-6u45-linux-x64-rpm.bin

# Switch back to jboss user
USER jboss

# Set the JAVA_HOME variable to make it clear where Java is located
ENV JAVA_HOME /usr/java/jdk1.6.0_45

# Add the jboss as distribution
RUN cd $HOME \
    && wget -O jboss-as-distribution-6.0.0.Final.zip http://sourceforge.net/projects/jboss/files/JBoss/JBoss-6.0.0.Final/jboss-as-distribution-6.0.0.Final.zip/download \
    && wget -O jboss-as-distribution-6.0.0.Final.zip.sha1 http://sourceforge.net/projects/jboss/files/JBoss/JBoss-6.0.0.Final/jboss-as-distribution-6.0.0.Final.zip.sha1/download \
    && sha1sum jboss-as-distribution-6.0.0.Final.zip.sha1 \
    && unzip jboss-as-distribution-6.0.0.Final.zip \
    && rm jboss-as-distribution-6.0.0.Final.zip \
    && rm jboss-as-distribution-6.0.0.Final.zip.sha1 
    
EXPOSE 8080

CMD ["/opt/jboss/jboss-6.0.0.Final/bin/run.sh", "-c", "default", "-b", "0.0.0.0"]
