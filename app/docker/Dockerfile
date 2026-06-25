FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY app/docker/requirements.txt ./app/docker/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r app/docker/requirements.txt

COPY main.py ./main.py
COPY VK ./VK
COPY app/fastapi ./app/fastapi
COPY app/sql_save_service.py ./app/sql_save_service.py

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
