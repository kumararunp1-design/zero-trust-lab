FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY app.py .
COPY passkey_demo.html .
EXPOSE 3000
CMD ["python", "app.py"]
