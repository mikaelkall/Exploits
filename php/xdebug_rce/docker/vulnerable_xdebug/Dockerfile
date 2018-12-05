FROM centos:centos7.4.1708

RUN yum update -y
RUN yum --enablerepo=extras install -y epel-release httpd
RUN yum --enablerepo=extras install -y php php-pecl-xdebug

COPY xdebug.ini /etc/php.d/
COPY phpinfo.php /var/www/html/phpinfo.php

RUN mkdir /var/log/php
RUN chown apache /var/log/php

EXPOSE 80

CMD ["/usr/sbin/httpd","-X"]
