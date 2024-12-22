FROM python:3.12.3

# Set the working directory
WORKDIR /app

# Copy requirements.txt and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy application files
COPY . .

# Generate SSL certificates
RUN openssl genpkey -algorithm RSA -out server.key && \
    openssl req -new -key server.key -out server.csr -config openssl.cnf && \
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Run the server
CMD ["python", "gree_server.py"]
