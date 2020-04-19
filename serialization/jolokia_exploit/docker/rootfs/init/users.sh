#
# Script to create tomcat-users.xml

JOLOKIA_BASIC_AUTH="${JOLOKIA_BASIC_AUTH:-}"


enable_authentication() {

  file="${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml"

  sed -i \
    -e '/<\/web-app>/ d' \
    ${file}

  cat << EOF >> ${file}

  <login-config>
    <auth-method>BASIC</auth-method>
    <realm-name>Jolokia</realm-name>
  </login-config>

  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Jolokia-Agent Access</web-resource-name>
      <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <role-name>jolokia</role-name>
    </auth-constraint>
  </security-constraint>

  <security-role>
    <role-name>jolokia</role-name>
  </security-role>

</web-app>
EOF
}


create_login_user() {

  local users=

  [[ -n "${JOLOKIA_BASIC_AUTH}" ]] && users=$(echo ${JOLOKIA_BASIC_AUTH} | sed -e 's/,/ /g' -e 's/\s+/\n/g' | uniq)

  if [[ ! -z "${users}" ]]
  then
    log_info "create basic auth users ..."

      users_xml="${CATALINA_HOME}/conf/tomcat-users.xml"

      cat << EOF > ${users_xml}
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="jolokia"/>
EOF

    for u in ${users}
    do
      user=$(echo "${u}" | cut -d: -f1)
      pass=$(echo "${u}" | cut -d: -f2)

      [[ -z ${pass} ]] && pass=${user}

      log_info "  - '${user}'"

      cat << EOF >> ${users_xml}
  <user username="${user}" password="${pass}" roles="jolokia"/>
EOF
    done

    echo "</tomcat-users>" >> ${users_xml}

    enable_authentication
  fi
}

create_login_user


# EOF
