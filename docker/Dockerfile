# syntax=docker/dockerfile:1

FROM python:3.11-slim

WORKDIR /app
COPY . /app

COPY ./docker/uwsgi/uwsgi.ini /app/uwsgi.ini

RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python initialize_db.py
RUN apt-get update && apt-get install -y \
    uwsgi \
    uwsgi-plugin-python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/

RUN mkdir -p /var/log/uwsgi
RUN chown -R www-data:www-data /var/log/uwsgi
RUN chown -R www-data:www-data /app

CMD ["uwsgi", "--ini", "/app/uwsgi.ini"]
