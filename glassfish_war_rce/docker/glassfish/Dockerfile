FROM glassfish:latest
EXPOSE 8080 4848

ENV GLASSFISH_PATH /usr/local/glassfish4
ENV ADMIN_USER admin
ENV ADMIN_PASSWORD admin

# set credentials to admin/admin 
RUN echo 'AS_ADMIN_PASSWORD=\n\
AS_ADMIN_NEWPASSWORD='$ADMIN_PASSWORD'\n\
EOF\n'\
>> /opt/tmpfile

RUN echo 'AS_ADMIN_PASSWORD='$ADMIN_PASSWORD'\n\
EOF\n'\
>> /opt/pwdfile

RUN \
 $GLASSFISH_PATH/bin/asadmin start-domain && \
 $GLASSFISH_PATH/bin/asadmin --user $ADMIN_USER --passwordfile=/opt/tmpfile change-admin-password && \
 $GLASSFISH_PATH/bin/asadmin --user $ADMIN_USER --passwordfile=/opt/pwdfile enable-secure-admin && \
 $GLASSFISH_PATH/bin/asadmin restart-domain

COPY start.sh /

# cleanup
RUN rm /opt/tmpfile

ENTRYPOINT ["/start.sh"]
