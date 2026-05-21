FROM ubuntu@sha256:d4f6f70979d0758d7a6f81e34a61195677f4f4fa576eaf808b79f17499fd93d1

RUN apt-get update && apt-get install -y --no-install-recommends make gcc socat build-essential

WORKDIR /challenge

COPY --chown=root:root gym_notes.c Makefile flag .

RUN make

RUN rm -f Makefile gym_notes.c

RUN chmod 444 ./flag

CMD ["socat", "-d", "tcp-listen:1337,fork,reuseaddr", "EXEC:'./gym_notes',su=nobody,stderr"]
