# Multi-stage build for PCI Segment
FROM golang:1.25.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make clang llvm libbpf-dev linux-headers

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o pci-segment .

# Build eBPF programs (for Linux deployments)
RUN cd pkg/enforcer/bpf && make clean && make

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libbpf

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/pci-segment /app/
COPY --from=builder /build/pkg/enforcer/bpf/pci_segment.o /app/pkg/enforcer/bpf/

# Copy example policies
COPY examples/policies /app/examples/policies

# Create non-root user
RUN addgroup -g 1000 pci && \
    adduser -D -u 1000 -G pci pci && \
    chown -R pci:pci /app

USER pci

ENTRYPOINT ["/app/pci-segment"]
CMD ["--help"]
