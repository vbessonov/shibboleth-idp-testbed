FROM python:2.7

RUN apt-get update && \
  apt-get install -y libxmlsec1-dev libxml2-dev && \
  apt-get clean

COPY requirements.txt .
RUN pip install pip --upgrade && \
  pip install setuptools --upgrade && \
  pip install -rrequirements.txt

ENV FLASK_APP=flaskr/__init__.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0

WORKDIR /app
COPY flaskr /app/flaskr

CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]
