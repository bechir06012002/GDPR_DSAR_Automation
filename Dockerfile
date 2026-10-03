FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dsar_processor.py .

CMD ["python", "-m", "uvicorn", "dsar_processor:app", "--host", "0.0.0.0", "--port", "8000"]