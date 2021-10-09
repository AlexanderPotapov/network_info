FROM python:3-alpine
LABEL maintainer="WhiteApfel <white@pfel.ru>"

RUN adduser -h /app -g app -D app

COPY . /app
COPY requirements.txt /app/requirements.txt

WORKDIR /app

RUN apk add --no-cache bash postgresql-libs \
  && apk add --no-cache --virtual .builddeps build-base postgresql-dev \
  && pip install -r requirements.txt \
  && apk del --no-cache .builddeps

RUN chown -R app:app /app
USER app

# RUN mkdir -p databases

CMD ["--help"]
