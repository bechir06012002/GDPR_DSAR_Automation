FROM python:3.9-slim

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY dsar_processor.py .

# Copy dashboard static files
COPY static/ static/

# Run app
CMD ["python", "-m", "uvicorn", "dsar_processor:app", "--host", "0.0.0.0", "--port", "8000"]