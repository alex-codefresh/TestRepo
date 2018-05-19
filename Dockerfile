FROM alpine
ARG TEST=default
RUN mkdir /app
RUN echo ${TEST}
