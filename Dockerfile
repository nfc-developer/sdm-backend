FROM tiangolo/uwsgi-nginx-flask:python3.7

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache -r /tmp/requirements.txt

COPY . /app
COPY uwsgi.docker.ini /app/uwsgi.ini
COPY config.docker.py /app/config.py
