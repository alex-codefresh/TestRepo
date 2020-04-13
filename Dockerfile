FROM alpine as test

WORKDIR /myapp

COPY . .

FROM test as test2
