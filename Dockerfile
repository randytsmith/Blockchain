FROM python:3.6-alpine

WORKDIR /usr/src/app
COPY ./scalamed/ .
COPY ./requirements.txt .

RUN apk update

# For compiling anything in C/C++; including Cython
RUN apk add build-base

# For install cffi, a dependency of bcrypt:
RUN apk add libffi-dev openssl-dev

RUN pip install -r requirements.txt

RUN ./manage makemigrations
RUN ./manage migrate

ENTRYPOINT ["python3"]
CMD ["/usr/src/app/manage", "runserver", "0.0.0.0:8000"]

