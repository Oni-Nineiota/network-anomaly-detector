FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Generate sample logs
RUN python log_generator.py

# Expose port
EXPOSE 5000

# Run the app
CMD ["python", "-c", "from app import app; app.run(host='0.0.0.0', port=5000, debug=False)"]
