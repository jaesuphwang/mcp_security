FROM python:3.11-slim

WORKDIR /app

# Copy and run a simple Python script
COPY app.py .

# Expose port 8080
EXPOSE 8080

# Run the application
CMD ["python", "app.py"] 