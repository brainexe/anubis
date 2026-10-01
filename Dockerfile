# Stage 1: Builder (Combined Node.js + Go)
FROM golang:1.25-bookworm AS builder

# Install Node.js 24.x, compression tools, and build essentials
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && \
    apt-get install -y nodejs build-essential zstd brotli

WORKDIR /app

# Copy dependency files first (for caching)
COPY package.json package-lock.json go.mod go.sum ./

# Install dependencies
RUN npm ci && go mod download

# Copy source code
COPY . .

# Build assets (runs web/build.sh, xess/build.sh)
RUN npm run assets

# Build binary with static linking
ARG VERSION
RUN CGO_ENABLED=0 go build -ldflags="-extldflags '-static' -X github.com/TecharoHQ/anubis.Version=${VERSION}" \
    -o /anubis ./cmd/anubis

# Stage 2: Final Image
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /anubis /anubis

USER 1000

ENTRYPOINT ["/anubis"]
