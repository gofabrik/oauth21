FROM golang:1.26.10 AS build
WORKDIR /src
COPY . .
RUN cd examples && CGO_ENABLED=0 go build -o /bin/server ./demo/server
RUN cd tools && CGO_ENABLED=0 go build -o /bin/oauch ./oauch

FROM gcr.io/distroless/static-debian12 AS server
COPY --from=build /bin/server /server
ENTRYPOINT ["/server", "-cert-out", "/tmp/demo-ca.pem"]

FROM gcr.io/distroless/static-debian12 AS driver
COPY --from=build /bin/oauch /oauch
ENTRYPOINT ["/oauch"]
