#!/bin/bash

# Start a dummy SMTP server to log errors
python -m smtpd -nc DebuggingServer localhost:2525 &

python manage.py celeryd -E -B --beat --concurrency=1 &
gunicorn wsgi:application -b 0.0.0.0:$PORT -w 8
