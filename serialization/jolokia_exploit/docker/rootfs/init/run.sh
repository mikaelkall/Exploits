#!/bin/sh

. /init/output.sh

enable_proxy() {

  export JOLOKIA_JSR160_PROXY_ENABLED=1

  if ( [ -d ${CATALINA_HOME}/webapps/jolokia ] && [ -f /opt/web-tpl.xml ] )
  then
    mv ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml-DIST
    cp /opt/web-tpl.xml ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml
    # diff ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml-DIST ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml
  fi
}

enable_debug() {

  # see https://jolokia.org/reference/html/agents.html#war-agent-installation for full examples
  if ( [ ${DEBUG} ] && [ "${DEBUG}" = "true" ] || [ "${DEBUG}" = "1" ] )
  then
    DEBUG="true"
  else
    DEBUG="false"
  fi

  sed -i \
    -e "s|%DEBUG_ENABLED%|${DEBUG}|g" \
    ${CATALINA_HOME}/webapps/jolokia/WEB-INF/web.xml
}

# side channel to inject some wild-style customized scripts
#
custom_scripts() {

  if [ -d /init/custom.d ]
  then
    for f in /init/custom.d/*
    do
      case "$f" in
        *.sh)
          log_info "RUN SCRIPT: ${f}"
          nohup "${f}" > /dev/stdout 2>&1 &
          ;;
          #echo "$0: running $f"; . "$f" ;;
        *)
          log_warn "ignoring file ${f}"
          ;;
      esac
      echo
    done
  fi
}

run_tomcat() {

  set +x

  # set pid file
  CATALINA_PID="${CATALINA_HOME}/temp/catalina.pid"
  # set memory settings
  # export JAVA_OPTS="-Xmx256M ${JAVA_OPTS}"
  # https://github.com/rhuss/jolokia/issues/222#issuecomment-170830887
  # 30s timeout
  CATALINA_OPTS="${CATALINA_OPTS} -Xms256M"
  CATALINA_OPTS="${CATALINA_OPTS} -Xmx1025m"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:NewSize=256m"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:MaxNewSize=256m"
  #CATALINA_OPTS="${CATALINA_OPTS} -XX:PermSize=256m"
  #CATALINA_OPTS="${CATALINA_OPTS} -XX:MaxPermSize=256m"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:+DisableExplicitGC"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:HeapDumpPath=/var/logs/"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:+HeapDumpOnOutOfMemoryError"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:+UseConcMarkSweepGC"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:+UseParNewGC"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:SurvivorRatio=8"
  CATALINA_OPTS="${CATALINA_OPTS} -XX:+UseCompressedOops"
  CATALINA_OPTS="${CATALINA_OPTS} -Dserver.name=${HOSTNAME}"
  CATALINA_OPTS="${CATALINA_OPTS} -Dcom.sun.management.jmxremote.port=22222"
  CATALINA_OPTS="${CATALINA_OPTS} -Dcom.sun.management.jmxremote.authenticate=false"
  CATALINA_OPTS="${CATALINA_OPTS} -Dcom.sun.management.jmxremote.ssl=false"
  CATALINA_OPTS="${CATALINA_OPTS} -Dsun.rmi.transport.tcp.responseTimeout=30000"

  export CATALINA_PID
  export JAVA_OPTS
  export CATALINA_OPTS

  /bin/sh -e /opt/tomcat/bin/catalina.sh run
}

run() {

  enable_proxy
  enable_debug

  . /init/users.sh

  custom_scripts
  run_tomcat
}

run

# EOF
