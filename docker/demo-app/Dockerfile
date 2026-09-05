FROM python:3.12-slim

RUN useradd --create-home --uid 10001 demoapp
USER demoapp
WORKDIR /home/demoapp

COPY --chown=demoapp:demoapp app.py .

EXPOSE 9000
CMD ["python", "app.py"]
