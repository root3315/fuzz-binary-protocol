# Binary Protocol Fuzzer

A C++ fuzzing framework for testing binary protocol implementations. This tool generates mutated binary inputs to discover crashes, hangs, and edge cases in protocol parsers and handlers.

## Features

- **Multiple Mutation Strategies**: Bit flips, byte operations, arithmetic mutations, block operations, magic bytes, and boundary value testing
- **Coverage-Guided Fuzzing**: Track execution coverage to prioritize interesting inputs
- **Corpus Management**: Maintain and evolve a corpus of interesting test cases
- **Crash Detection**: Automatically detect and save crashing inputs
- **Minimization**: Reduce crash inputs to minimal reproducing cases
- **Extensible Architecture**: Easy to add custom mutation strategies and execution callbacks

## Project Structure

```
fuzz-binary-protocol/
├── include/
│   ├── protocol.h      # Binary protocol definitions and codec
│   ├── mutator.h       # Mutation strategies and engine
│   └── fuzzer.h        # Core fuzzer classes
├── src/
│   ├── protocol.cpp    # Protocol encoding/decoding
│   ├── mutator.cpp     # Mutation implementations
│   ├── fuzzer.cpp      # Fuzzer engine implementation
│   └── main.cpp        # CLI entry point
├── tests/
│   └── test_fuzzer.cpp # Unit and integration tests
├── CMakeLists.txt      # Build configuration
└── README.md           # This file
```

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.14 or higher
- POSIX-compatible system (Linux, macOS)

## Installation

### Build from Source

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Build Options

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Install to custom prefix
cmake -DCMAKE_INSTALL_PREFIX=/opt/fuzzer ..
```

### Install

```bash
sudo make install
```

## Usage

### Basic Fuzzing

Run with default settings (simulated target):

```bash
./fuzz-binary-protocol -n 10000
```

### With Corpus Directory

```bash
./fuzz-binary-protocol -c ./seeds -o ./output -n 100000
```

### With Custom Target

```bash
./fuzz-binary-protocol -c ./corpus -o ./output -t "./target_binary @@" -n 50000
```

### Generate Sample Inputs

```bash
# Generate handshake message
./fuzz-binary-protocol -g handshake

# Generate data message
./fuzz-binary-protocol -g data

# Generate heartbeat message
./fuzz-binary-protocol -g heartbeat
```

### List Mutation Strategies

```bash
./fuzz-binary-protocol -l
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-c, --corpus DIR` | Input corpus directory |
| `-o, --output DIR` | Output directory for crashes/corpus |
| `-t, --target CMD` | Target command to execute |
| `-s, --seed NUM` | Random seed (default: random) |
| `-n, --iterations NUM` | Maximum iterations (0 = unlimited) |
| `-T, --timeout US` | Execution timeout in microseconds |
| `-M, --max-size BYTES` | Maximum input size |
| `-m, --min-size BYTES` | Minimum input size |
| `-p, --mutations NUM` | Mutations per input |
| `-g, --generate TYPE` | Generate sample input |
| `-l, --list-strategies` | List mutation strategies |
| `-v, --verbose` | Verbose output |
| `-d, --dry-run` | Test configuration without fuzzing |
| `-h, --help` | Show help |

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Fuzzer Engine                        │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   Corpus    │  │   Mutator   │  │    Coverage     │ │
│  │   Manager   │  │   Engine    │  │    Tracker      │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
│         │                │                  │           │
│         └────────────────┼──────────────────┘           │
│                          │                              │
│                 ┌────────▼────────┐                     │
│                 │  Input Generator │                    │
│                 └────────┬────────┘                     │
└──────────────────────────┼──────────────────────────────┘
                           │
                           ▼
                 ┌─────────────────┐
                 │  Target Binary  │
                 │  (via callback) │
                 └─────────────────┘
```

### Fuzzing Loop

1. **Select Input**: Choose from corpus or generate fresh input
2. **Mutate**: Apply random mutation strategies
3. **Execute**: Run target with mutated input
4. **Analyze**: Check for crashes, timeouts, new coverage
5. **Update**: Add interesting inputs to corpus
6. **Repeat**: Continue until iteration limit or interruption

### Mutation Strategies

| Strategy | Description |
|----------|-------------|
| BitFlip | Flip random bits in the input |
| ByteFlip | Replace bytes with random values |
| ByteInsert | Insert random bytes |
| ByteRemove | Remove bytes from input |
| ByteDuplicate | Duplicate existing bytes |
| Arithmetic | Add/subtract from numeric values |
| InterestingValue | Insert known interesting values (0, -1, MAX_INT, etc.) |
| BlockInsert | Insert random byte blocks |
| BlockRemove | Remove byte blocks |
| BlockDuplicate | Duplicate byte blocks |
| ShuffleBytes | Shuffle bytes within a region |
| MagicBytes | Insert common magic byte sequences |
| BoundaryValue | Test boundary values (0x00, 0x7F, 0x80, 0xFF) |

### Protocol Format

The fuzzer includes a sample binary protocol:

```
Header (8 bytes):
  Offset  Size  Description
  0       2     Magic bytes (0xBE, 0xEF)
  2       1     Message type
  3       1     Flags
  4       2     Sequence number (big-endian)
  6       2     Payload length (big-endian)

Payload (variable):
  Followed by payload_len bytes of data
```

Message Types:
- `0x01` - HANDSHAKE
- `0x02` - DATA
- `0x03` - ACK
- `0x04` - NACK
- `0x05` - HEARTBEAT
- `0x06` - DISCONNECT
- `0xFF` - CUSTOM

## Running Tests

```bash
cd build
ctest --verbose

# Run specific test suites
./test_fuzzer protocol
./test_fuzzer mutator
./test_fuzzer fuzzer
./test_fuzzer integration
```

## Library Usage

The fuzzer can be used as a library in your own projects:

```cpp
#include "fuzzer.h"
#include "protocol.h"

using namespace fuzzproto;

int main() {
    FuzzerConfig config;
    config.seed = 42;
    config.max_iterations = 10000;
    
    Fuzzer fuzzer(config);
    
    // Set execution callback
    fuzzer.setExecutionCallback([](const std::vector<uint8_t>& input) {
        ExecutionResult result;
        
        // Your target execution logic here
        // Return CRASH, TIMEOUT, or OK
        
        result.status = ExecutionResult::OK;
        result.coverage = computeCoverage(input);
        return result;
    });
    
    // Add seed inputs
    auto handshake = ProtocolCodec::createHandshake(1, 0);
    fuzzer.addSeed(handshake);
    
    // Run fuzzer
    fuzzer.run();
    
    return 0;
}
```

## Output

The fuzzer produces real-time progress output:

```
[1m 30s] Execs: 50000 (555/s) | Crashes: 3 | Corpus: 127

Fuzzing complete!
  Total time: 1m 30s
  Total executions: 50000
  Executions/second: 555.5
  Crashes found: 3
  Corpus size: 127
```

Crashes are saved to the output directory with details about the crashing input.

## Tips for Effective Fuzzing

1. **Start with valid seeds**: Provide valid protocol messages as initial corpus
2. **Tune mutation rate**: Adjust mutations per input based on target complexity
3. **Use coverage feedback**: Implement coverage tracking for better exploration
4. **Set appropriate timeouts**: Balance between catching hangs and performance
5. **Monitor crashes**: Review and triage found crashes regularly

## License

This project is provided as-is for educational and testing purposes.

## Contributing

Contributions are welcome. Please ensure:
- Code follows C++17 standards
- Tests pass with `ctest`
- No memory leaks (use valgrind/ASan)
- Documentation is updated
