FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p output

CMD ["python", "scanner.py"]
