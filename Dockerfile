FROM python:alpine3.21

WORKDIR /app

COPY requirements.txt .
COPY cert.pem .
COPY key.pem .
CMD ["chmod", "400", "./*.pem"]
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]