FROM ubuntu:24.04

RUN apt update && apt install -y socat

COPY flag.txt /
RUN chmod 444 /flag.txt

WORKDIR /app

# NOTE: main will use the provided libc and ld, NOT the ubuntu ones.
COPY main libc.so.6 ld-linux-x86-64.so.2 ./


EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,fork,reuseaddr", "exec:/app/main"]
