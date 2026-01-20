FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Cloudtype, 로컬 어디서든 무조건 살아남게 만드는 핵심
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:5000 app:app"]