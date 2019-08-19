# image base
FROM python:3

WORKDIR /opt/pefixup/

RUN apt-get update && \
  	apt-get install -y --no-install-recommends \
  	libffi-dev \
  	libfuzzy-dev \
  	ssdeep


COPY ./requirements.txt /opt/pefixup/requirements.txt

RUN pip install -r requirements.txt

ENTRYPOINT ["pe_fixup.py"]