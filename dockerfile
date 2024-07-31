# golang 이미지를 사용
FROM golang:1.22.3-alpine AS builder

# work dir
WORKDIR /home/server

# host pc의 현재경로의 디렉토리를 workdir 의 디렉토리로 복사
COPY . .


EXPOSE 8080

RUN GOOS=linux GOARCH=amd64 go build -o main

# 8080 포트 오픈

CMD [ "./main" ]
