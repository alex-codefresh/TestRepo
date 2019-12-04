FROM alpine as test

COPY . .

FROM test as test2
