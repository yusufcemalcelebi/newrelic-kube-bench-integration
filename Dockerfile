FROM python:3.12.0a1-slim

LABEL Maintainer="yusufcelebi@teambion.com"

WORKDIR /usr/app/src

COPY kube-bench-NR-forwarder.py ./

#TODO: pip install 

CMD [ "python", "./kube-bench-NR-forwarder.py"]