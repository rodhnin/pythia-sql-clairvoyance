# ============================================================================
# Pythia SQL Injection Scanner - Docker Image
# ============================================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="Rodney Dhavid Jimenez Chacin (rodhnin)"
LABEL description="Pythia - SQL Injection Detection Scanner"
LABEL version="0.1.0"
LABEL website="https://rodhnin.com"

# Create non-root user (same pattern as Argus)
RUN useradd -m -u 1000 pythia

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY . /app/

# Install Pythia in development mode
RUN pip install -e .

# Create directories for data persistence and set permissions
RUN mkdir -p /data /reports && \
    chown -R pythia:pythia /app /data /reports

# Switch to non-root user
USER pythia

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Expose port (if needed for future web interface)
# EXPOSE 8000

# Entry point (allows running arbitrary Python commands)
ENTRYPOINT ["python", "-m", "pyth"]

# Default command (show help)
CMD ["--help"]