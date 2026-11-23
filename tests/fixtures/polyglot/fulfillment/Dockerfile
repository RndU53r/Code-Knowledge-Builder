FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/worker ./cmd/worker && CGO_ENABLED=0 go build -o /out/pricing ./cmd/pricing

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/worker /worker
USER nonroot
ENTRYPOINT ["/worker"]
