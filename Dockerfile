FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt setup.py pyproject.toml ./
RUN pip install --no-cache-dir -e .

COPY . .

EXPOSE 8000

CMD ["python", "-m", "agentsentry.cli", "start", "--host", "0.0.0.0", "--port", "8000"]
