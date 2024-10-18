FROM golang:1.23.2 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -gcflags="all=-N -l" -o main .
#RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

#FROM alpine:3.20
FROM golang:1.23.2
#RUN apk --no-cache add ca-certificates
RUN go install github.com/go-delve/delve/cmd/dlv@latest
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 8000
EXPOSE 40000
#CMD ["./main"]
CMD ["dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "./main"]
