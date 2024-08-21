###### build stage ######
FROM golang:1.22.3-alpine AS builder

WORKDIR /home/server

COPY src /home/server/src

WORKDIR /home/server/src

RUN go mod download

RUN GOOS=linux GOARCH=amd64 go build -o main .

###### final stage ######
FROM alpine:latest

WORKDIR /home/server

COPY --from=builder /home/server/src/main .

EXPOSE 8080

CMD ["./main"]
