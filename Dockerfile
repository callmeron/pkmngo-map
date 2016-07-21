FROM phusion/baseimage:latest
MAINTAINER Matthew Baggett <matthew@baggett.me>

CMD ["/sbin/my_init"]

## Install base packages
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get -yq install \
        python-pip \
        python-dev \
        build-essential && \
    apt-get -yq upgrade && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip install --upgrade pip;


RUN mkdir /etc/service/scanner
RUN mkdir /etc/service/web
ADD docker/run.scanner.sh /etc/service/scanner/run
ADD docker/run.web.sh /etc/service/web/run
RUN chmod +x /etc/service/*/run

ADD . /app

RUN cd /app && pip install -r requirements.txt
