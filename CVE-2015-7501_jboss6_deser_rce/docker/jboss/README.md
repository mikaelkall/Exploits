# docker-jboss-6.0.0.final
Docker image that builds a JBOSS AS 6.0.0.final server along with JDK 1.6.0_45.

Note: because of the licence restrictions of the Oracle JDK, I cannot push a pre-built image on the Docker hub. You have to build the image yourself and download (and accept) yourself the Terms & Conditions of the Oracle JDK.

First you need to download the Oracle JDK 1.6.0_45 rpm package.
This is required because JBOSS AS 6.0.0.final works with a JDK 6 runtime.
After testing, it appeared that the OpenJDK gives a ClassCastException when starting the application server. Relying on the Oracle JDK allows to run the application server directly.

Because you must accept the Terms and Conditions of Oracle prior to installing the Oracle JDK, I have not bundled this into this project. You have to download it separately (and accept yourself the Terms and Conditions). In order to download the rpm, you can go to: http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javase6-419409.html#jdk-6u45-oth-JPR and download the jdk-6u45-linux-x64.rpm.bin package into the same directory as the Dockerfile.

In order to build this image just run the following command (it is assumed that Docker is installed properly either natively or with Boot2Docker and started):

    docker build -t ovanekem/docker-jboss-6.0.0.final .
  
Building the project will take some time as it downloads the JBOSS AS package from Sourceforge.

You can then either run this image or extend it.

In order to run it, run the following Docker command:

    docker run -it -p 8080:8080 ovanekem/docker-jboss-6.0.0.final
  
You can now access (replace <ip_of_docker> with either localhost or the ip of Boot2Docker) http://<ip_of_docker>:8080/admin-console.
You can log into the administration console of JBOSS using admin as login and admin as password.

In order to extend this image, you can simply write your own Dockerfile that extends this image:

    FROM ovanekem/docker-jboss-6.0.0.final:latest

And customize your image with your project's specifics, for example copy a local run.conf to the container,...

    