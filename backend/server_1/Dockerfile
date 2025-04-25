# Use Python 3.9 as the base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Copy application files correctly
COPY backend/server_1/server_1.py /app/
COPY backend/server_1/requirements.txt /app/

# Copy the shared folder
COPY backend/shared /app/shared

# Copy dataset
COPY backend/dataset /app/dataset

# Set PYTHONPATH so Python can find the shared module
ENV PYTHONPATH=/app

# Upgrade pip to avoid issues
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose the Flask server port
EXPOSE 5001

# Start the application using Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "server_1:app"]
