FROM ubuntu:22.04 as base
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y                                                       \
       python3-venv                                                          \
       python3-pip                                                           \
       python3-dev                                                           \
       git

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN mkdir /build
WORKDIR /build
COPY docs/ /build/docs
COPY mkdocs.yml /build

RUN python3 -m pip install "tomte[docs]==0.6.5"
RUN python3 -m pip install git+https://github.com/pugong/mkdocs-mermaid-plugin.git
RUN mkdocs build

FROM python:3.10-alpine
COPY --from=base /build/site /site

WORKDIR /site
CMD ["python3", "-m", "http.server"]
