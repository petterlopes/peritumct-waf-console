FROM python:3.12-slim-bookworm
WORKDIR /app
COPY app.py control.py catalog.py correlate.py ga.py /app/
COPY static /app/static
ENV WAF_BIND=127.0.0.1
ENV WAF_PORT=18990
ENV PYTHONUNBUFFERED=1
EXPOSE 18990
USER nobody
CMD ["python", "-u", "/app/app.py"]
