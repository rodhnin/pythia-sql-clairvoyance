# Flask Vulnerable App Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-lab.txt /app/
RUN pip install --no-cache-dir -r requirements-lab.txt

# Copy application code
COPY app.py /app/

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Run Flask
CMD ["python", "app.py"]