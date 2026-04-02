FROM python:3.9

WORKDIR /app

RUN pip install "setuptools<59.6.0"
RUN pip install ryu eventlet==0.30.2 tinyrpc pyyaml
ENV PYTHONPATH="/app"
COPY . /app

EXPOSE 6635 8080

CMD ["python3", "controller/main_controller.py"]
