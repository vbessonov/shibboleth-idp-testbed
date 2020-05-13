FROM python:2.7

RUN apt-get update && \
  apt-get install -y libxmlsec1-dev libxml2-dev && \
  apt-get clean

COPY requirements.txt .
RUN pip install pip --upgrade && \
  pip install setuptools --upgrade && \
  pip install -rrequirements.txt

COPY . /app

CMD ["python", "/app/index.py"]
