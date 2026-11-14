FROM python:3.12-slim

ADD requirements.txt /root/requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip --trusted-host pypi.python.org -r /root/requirements.txt

ENTRYPOINT /bin/bash

EXPOSE 5000
