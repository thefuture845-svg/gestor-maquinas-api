FROM python:3.12-slim

WORKDIR /app

COPY servidor.py .

EXPOSE 8080

CMD ["python3", "servidor.py"]
