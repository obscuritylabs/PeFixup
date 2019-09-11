# image base
FROM python:3

WORKDIR /opt/pefixup/

RUN apt-get update && \
  	apt-get install -y --no-install-recommends \
  	libffi-dev \
  	libfuzzy-dev \
  	ssdeep


COPY . /opt/pefixup/

RUN pip install -r requirements.txt

ENTRYPOINT ["pefixup.py"]