FROM python:3.11-slim

WORKDIR /app

# 시스템 패키지(선택): psycopg2-binary는 보통 추가 패키지 없이도 동작
# 필요 시 아래 주석 해제
# RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# cloudtype가 PORT 환경변수를 주는 경우가 많아서 그대로 사용
ENV PORT=5000
EXPOSE 5000

CMD ["python", "app.py"]
