FROM python:3.11-slim

ENV DEBIAN_FRONTEND noninteractive
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

RUN apt update && apt install -y python3.11-dev python3-pip -y && apt autoremove && apt autoclean

RUN pip3 install --upgrade pip
RUN pip3 install "open-aea[all]==2.0.0" open-aea-cli-ipfs==2.0.0

COPY user-image/openssl.cnf /etc/ssl

WORKDIR /root

ENTRYPOINT ["/bin/bash", "-c"]
