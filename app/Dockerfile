# ---------- build stage ----------
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-w -s" -o devops-lab .

# ---------- runtime stage ----------
FROM scratch

# Non-root user (numeric — scratch has no /etc/passwd)
USER 65534:65534

COPY --from=builder /src/devops-lab /devops-lab

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/devops-lab"]
