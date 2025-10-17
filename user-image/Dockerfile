FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt update && apt upgrade -y && apt install -y python3-dev python3-pip && apt autoremove && apt autoclean

RUN pip3 install --upgrade pip
RUN pip3 install "open-aea[all]==2.0.7" open-aea-cli-ipfs==2.0.7

COPY user-image/openssl.cnf /etc/ssl

WORKDIR /root

ENTRYPOINT ["/bin/bash", "-c"]
