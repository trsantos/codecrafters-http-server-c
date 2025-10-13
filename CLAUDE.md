# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a CodeCrafters HTTP/1.1 server implementation in C (C23 standard). The project is part of the "Build Your Own HTTP server" challenge, where you build a TCP server capable of serving multiple clients using raw socket programming.

## Build System

- **Build tool**: CMake (minimum version 3.13)
- **Package manager**: vcpkg (configured via `vcpkg.json` and `vcpkg-configuration.json`)
- **C Standard**: C23 (configured in `CMakeLists.txt`)
- **Binary name**: `http-server`

### Build Commands

```sh
# Build the project (builds to ./build/http-server)
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build ./build

# Run the server locally
./your_program.sh

# The your_program.sh script does both: compiles and runs the server
```

## Development Workflow

### Testing on CodeCrafters

CodeCrafters automatically tests your code when you push to the master branch:

```sh
git commit -am "your commit message"
git push origin master
```

The test output will be streamed to your terminal. The `.codecrafters/` directory contains the compile and run scripts used by the CodeCrafters platform (don't modify these directly).

### Local Development

1. Edit code in `src/main.c` (currently the only source file)
2. Run `./your_program.sh` to compile and start the server
3. The server listens on port 4221 by default
4. Test with curl or a browser: `curl http://localhost:4221/`

## Code Architecture

### Current Implementation (src/main.c)

The current implementation is a basic TCP server skeleton:

- **Socket creation**: Creates a TCP socket with `AF_INET` and `SOCK_STREAM`
- **Socket options**: Uses `SO_REUSEADDR` to avoid "Address already in use" errors during rapid restarts
- **Binding**: Binds to port 4221 on all interfaces (`INADDR_ANY`)
- **Listening**: Accepts incoming connections with a backlog of 5
- **Response**: Currently sends a hardcoded HTTP 200 OK response to the first client
- **Limitation**: Only handles one client connection then exits - needs to be extended for multiple clients

### Key Technical Details

- The server uses standard POSIX socket APIs (`socket`, `bind`, `listen`, `accept`, `send`)
- Output buffering is disabled for stdout/stderr to ensure debug messages appear immediately
- Error handling uses `strerror(errno)` to provide descriptive error messages
- The server structure uses designated initializers for `sockaddr_in` (C99+ feature)

### Expected Evolution

As you progress through CodeCrafters stages, you'll likely need to:
- Add HTTP request parsing (parse method, path, headers, body)
- Implement routing logic for different endpoints
- Handle multiple concurrent connections (likely using fork/threads or select/poll/epoll)
- Support HTTP request methods (GET, POST, etc.)
- Implement proper HTTP response formatting with headers
- Add file serving capabilities
- Handle connection lifecycle properly (keep-alive vs close)

## Project Configuration

- **codecrafters.yml**: Controls CodeCrafters-specific settings (debug mode, language pack)
- **vcpkg.json**: Package dependencies (currently empty, add dependencies here as needed)
- **CMakeLists.txt**: Automatically includes all `.c` and `.h` files from `src/` directory
