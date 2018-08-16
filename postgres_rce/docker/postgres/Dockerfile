FROM library/postgres:11 
EXPOSE 5433 5432

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    python \
    netcat \
    && rm -rf /var/lib/apt/lists/*
