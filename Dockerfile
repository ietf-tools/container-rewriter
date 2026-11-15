FROM python:3.13

ENV FORWARDING_ADDR=forwardingalgorithm@myaddr.com
ENV FORWARDING_DOMAIN=myaddr.com
ENV LISTENING_PORT=8800

WORKDIR /app
COPY requirements.txt /app

RUN apt-get update && \
    apt-get install -fy --no-install-recommends libmilter-dev && \
    apt-get -fy dist-upgrade && \
    apt-get clean autoclean && \
    apt-get autoremove --yes && \
    rm -rf /var/lib/{apt,dpkg,cache,log} && \
    pip install -r requirements.txt && \
    groupadd --gid 10001 rewriter && \
    useradd --uid 10001 --gid rewriter --no-create-home --shell /usr/sbin/nologin rewriter && \
    chgrp rewriter /var/log && chmod g+w /var/log


ADD . /app

# numeric, so Kubernetes runAsNonRoot can check it; the chart's fsGroup
# and runAsUser use the same ids
USER 10001:10001

EXPOSE 8800

EXPOSE 8000

CMD ["python", "/app/rewriter.py"]
