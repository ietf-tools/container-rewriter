FROM python:3.13

ENV FORWARDING_ADDR=forwardingalgorithm@myaddr.com
ENV FORWARDING_DOMAIN=myaddr.com
ENV LISTENING_PORT=8800

ADD . /app

WORKDIR /app

RUN apt-get update && \
    apt-get install -fy --no-install-recommends libmilter-dev && \
    apt-get -fy dist-upgrade && \
    apt-get clean autoclean && \
    apt-get autoremove --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log} && \
    pip install -r requirements.txt && \
    adduser rewriter

USER rewriter

EXPOSE 8800

CMD ["python", "/app/rewriter.py"]
