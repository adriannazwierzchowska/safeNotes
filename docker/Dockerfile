# syntax=docker/dockerfile:1

FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python initialize_db.py
RUN apt-get update && apt-get install -y \
    nginx \
    uwsgi \
    uwsgi-plugin-python3 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/nginx/

COPY safenotes.crt /etc/nginx/
COPY safenotes.key /etc/nginx/

COPY uwsgi.ini /app/
COPY nginx.conf /etc/nginx/

EXPOSE 80
ENV FLASK_ENV=production

CMD ["sh", "-c", "service nginx start && python initialize_db.py && uwsgi --ini /app/uwsgi.ini"]
