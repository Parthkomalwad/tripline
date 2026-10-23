set windows-shell := ["bash", "-c"]

version := "dev"
ldflags := "-s -w -X github.com/Parthkomalwad/tripline/internal/version.Version=" + version
image := "tripline:local"

# List recipes.
default:
    @just --list

# Build a static binary for this machine.
build:
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="{{ldflags}}" -o bin/ ./cmd/tripline

# Build the static Linux binary that goes into the image.
build-linux:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="{{ldflags}}" -o bin/tripline-linux-amd64 ./cmd/tripline

# Verify modules, vet and test.
test:
    go mod verify
    go vet ./...
    go test ./...

# Build the container image.
image: build-linux
    docker build -t {{image}} .

# Run the image as non-root on a read-only filesystem and check it.
image-check: image
    test "$(docker image inspect -f '{{{{.Config.User}}' {{image}})" = "65532:65532"
    docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges {{image}} version

# Run the attack replay lab (needs Docker). LEVEL 2 only for now.
replay level="2" mode="monitor": build-linux
    bash replays/litellm-2026-10/run.sh {{level}} {{mode}}
