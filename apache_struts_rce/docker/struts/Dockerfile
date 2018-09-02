FROM piesecurity/apache-struts2-cve-2017-5638
EXPOSE 8080
RUN set -ex; \
     \
     apt-get update; \
     apt-get install -y --no-install-recommends python; \
     rm -rf /var/lib/apt/lists/*;
