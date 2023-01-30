FROM python:3.12.0a1-slim

LABEL Maintainer="yusufcelebi@teambion.com"

WORKDIR /usr/app/src

COPY kube-bench-NR-forwarder.py ./
COPY requirements.txt ./
# Uncomment for local testing 
# COPY kube-bench-output.json ./

RUN pip3 install -r requirements.txt

CMD [ "python3", "./kube-bench-NR-forwarder.py"]