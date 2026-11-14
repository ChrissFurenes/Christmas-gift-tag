FROM golang:1.23 AS build
WORKDIR /app
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S -G app app && mkdir /data && chown app:app /data
WORKDIR /app
COPY --from=build /server /app/server
COPY --from=build /app/templates /app/templates
COPY --from=build /app/static /app/static
USER app
EXPOSE 8080
CMD ["/app/server"]
