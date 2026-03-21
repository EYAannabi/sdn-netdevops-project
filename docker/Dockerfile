FROM python:3.9

WORKDIR /app

RUN pip install "setuptools<59.6.0"
RUN pip install ryu eventlet==0.30.2 tinyrpc pyyaml

COPY . /app

EXPOSE 6653 8080

CMD ["python3", "controller/main_controller.py"]
