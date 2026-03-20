#include "fuzzer.h"
#include "protocol.h"
#include "mutator.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

using namespace fuzzproto;

namespace {

volatile std::sig_atomic_t g_signal_received = 0;

void signalHandler(int signal) {
    g_signal_received = signal;
}

struct Config {
    std::string corpus_dir;
    std::string output_dir;
    std::string target_cmd;
    uint32_t seed = 0;
    uint64_t max_iterations = 0;
    uint64_t timeout_us = 1000000;
    size_t max_input_size = 65535;
    size_t min_input_size = 8;
    size_t mutations_per_input = 4;
    bool verbose = false;
    bool dry_run = false;
    bool list_strategies = false;
    std::string generate_input;
};

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [OPTIONS]\n"
              << "\nBinary Protocol Fuzzer - Test binary protocol implementations\n"
              << "\nOptions:\n"
              << "  -c, --corpus DIR       Input corpus directory\n"
              << "  -o, --output DIR       Output directory for crashes/corpus\n"
              << "  -t, --target CMD       Target command to execute (optional)\n"
              << "  -s, --seed NUM         Random seed (default: random)\n"
              << "  -n, --iterations NUM   Maximum iterations (0 = unlimited)\n"
              << "  -T, --timeout US       Execution timeout in microseconds\n"
              << "  -M, --max-size BYTES   Maximum input size\n"
              << "  -m, --min-size BYTES   Minimum input size\n"
              << "  -p, --mutations NUM    Mutations per input\n"
              << "  -g, --generate TYPE    Generate sample input (handshake|data|heartbeat)\n"
              << "  -l, --list-strategies  List mutation strategies\n"
              << "  -v, --verbose          Verbose output\n"
              << "  -d, --dry-run          Test configuration without fuzzing\n"
              << "  -h, --help             Show this help\n"
              << "\nExamples:\n"
              << "  " << program << " -c ./corpus -o ./output -n 10000\n"
              << "  " << program << " -g handshake -v\n"
              << "  " << program << " -l\n";
}

void printStrategies() {
    MutatorEngine engine;
    std::cout << "Available mutation strategies:\n";
    for (const auto& name : engine.getStrategyNames()) {
        std::cout << "  - " << name << "\n";
    }
}

std::vector<uint8_t> readSeedFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw std::runtime_error("Cannot open seed file: " + path);
    }

    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!ifs.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Cannot read seed file: " + path);
    }

    return buffer;
}

void ensureDirectory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        mkdir(path.c_str(), 0755);
    }
}

std::string formatBytes(const std::vector<uint8_t>& data, size_t max_len = 64) {
    std::ostringstream ss;
    size_t len = std::min(data.size(), max_len);
    
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) ss << " ";
        ss << std::hex << std::setfill('0') << std::setw(2) 
           << static_cast<int>(data[i]);
    }
    
    if (data.size() > max_len) {
        ss << " ... (" << (data.size() - max_len) << " more bytes)";
    }
    
    return ss.str();
}

std::string formatDuration(std::chrono::steady_clock::duration duration) {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() % 1000;
    
    if (seconds >= 60) {
        return std::to_string(seconds / 60) + "m " + 
               std::to_string(seconds % 60) + "s";
    }
    return std::to_string(seconds) + "." + std::to_string(ms) + "s";
}

// Simulated target execution for testing
ExecutionResult simulateTarget(const std::vector<uint8_t>& input) {
    ExecutionResult result;
    result.status = ExecutionResult::OK;
    result.exit_code = 0;
    
    auto start = std::chrono::steady_clock::now();
    
    // Simulate processing time
    usleep(100);
    
    auto end = std::chrono::steady_clock::now();
    result.execution_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();
    
    // Parse the input to check for protocol validity
    ProtocolCodec codec;
    ParsedMessage msg = codec.decode(input);
    
    // Generate coverage based on message type
    if (msg.valid) {
        result.coverage.resize(256, 0);
        result.coverage[static_cast<size_t>(msg.header.type)] = 1;
        result.coverage[msg.header.flags % 256] = 1;
        
        // Check for interesting conditions
        if (msg.header.payload_len > 1000) {
            result.coverage[200] = 1;
        }
        
        // Simulate crash on specific patterns
        if (input.size() >= 4 && 
            input[0] == 0xBE && input[1] == 0xEF &&
            input[2] == 0xFF && input[3] == 0xFF) {
            result.status = ExecutionResult::CRASH;
            result.error_message = "Invalid message type 0xFF with flags 0xFF";
            result.exit_code = -11;
        }
        
        // Simulate timeout on large payloads
        if (msg.header.payload_len > 60000) {
            result.status = ExecutionResult::TIMEOUT;
            result.error_message = "Payload too large";
        }
    } else {
        // Invalid messages get different coverage
        result.coverage.resize(256, 0);
        result.coverage[255] = 1;
    }
    
    return result;
}

// Execute target with proper subprocess handling
static pid_t g_child_pid = -1;

static void cleanupChild(int /*signal*/) {
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGKILL);
        waitpid(g_child_pid, nullptr, WNOHANG);
    }
}

ExecutionResult executeTarget(const std::string& cmd, const std::vector<uint8_t>& input,
                               uint64_t timeout_us) {
    ExecutionResult result;
    result.status = ExecutionResult::ERROR;
    result.exit_code = -1;
    result.execution_time_us = 0;

    // Write input to temp file
    char temp_path[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        result.error_message = "Failed to create temp file";
        return result;
    }

    if (write(fd, input.data(), input.size()) != static_cast<ssize_t>(input.size())) {
        close(fd);
        unlink(temp_path);
        result.error_message = "Failed to write input";
        return result;
    }
    close(fd);

    // Parse command and arguments
    std::vector<char*> args;
    std::vector<char> cmd_buffer(cmd.begin(), cmd.end());
    cmd_buffer.push_back('\0');

    char* token = std::strtok(cmd_buffer.data(), " ");
    while (token) {
        args.push_back(token);
        token = std::strtok(nullptr, " ");
    }
    args.push_back(temp_path);
    args.push_back(nullptr);

    auto start = std::chrono::steady_clock::now();

    // Create pipe for stderr
    int stderr_pipe[2];
    if (pipe(stderr_pipe) != 0) {
        unlink(temp_path);
        result.error_message = "Failed to create pipe";
        return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        unlink(temp_path);
        result.error_message = "Fork failed";
        return result;
    }

    if (pid == 0) {
        // Child process
        close(stderr_pipe[0]);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stderr_pipe[1]);

        // Set resource limits
        struct rlimit rl;
        rl.rlim_cur = 256 * 1024 * 1024;
        rl.rlim_max = 256 * 1024 * 1024;
        setrlimit(RLIMIT_AS, &rl);

        rl.rlim_cur = 60;
        rl.rlim_max = 60;
        setrlimit(RLIMIT_CPU, &rl);

        execvp(args[0], args.data());
        _exit(127);
    }

    // Parent process
    close(stderr_pipe[1]);
    fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK);
    g_child_pid = pid;

    // Set up timeout using select on the pipe
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(stderr_pipe[0], &readfds);

    int select_result = select(stderr_pipe[0] + 1, &readfds, nullptr, nullptr, &tv);
    (void)select_result;
    int status = 0;

    auto end = std::chrono::steady_clock::now();
    result.execution_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count();

    // Check if process completed
    pid_t wait_result = waitpid(pid, &status, WNOHANG);

    if (wait_result == 0) {
        // Timeout - kill child
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        result.status = ExecutionResult::TIMEOUT;
        result.error_message = "Timeout exceeded";
        result.execution_time_us = timeout_us;
    } else if (wait_result > 0) {
        if (WIFEXITED(status)) {
            result.exit_code = WEXITSTATUS(status);
            result.status = (result.exit_code == 0) ? ExecutionResult::OK : ExecutionResult::CRASH;
            if (result.status == ExecutionResult::CRASH) {
                result.error_message = "Exit code: " + std::to_string(result.exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            result.status = ExecutionResult::CRASH;
            result.exit_code = -WTERMSIG(status);
            result.error_message = "Killed by signal: " + std::to_string(-result.exit_code);
        }
    } else {
        result.error_message = "Waitpid failed";
    }

    close(stderr_pipe[0]);
    unlink(temp_path);
    g_child_pid = -1;

    return result;
}

void runFuzzer(const Config& config) {
    FuzzerConfig fuzzer_config;
    fuzzer_config.seed = config.seed;
    fuzzer_config.max_input_size = config.max_input_size;
    fuzzer_config.min_input_size = config.min_input_size;
    fuzzer_config.timeout_us = config.timeout_us;
    fuzzer_config.mutations_per_input = config.mutations_per_input;
    fuzzer_config.output_dir = config.output_dir;
    fuzzer_config.corpus_dir = config.corpus_dir;
    
    Fuzzer fuzzer(fuzzer_config);
    
    // Set up execution callback
    if (!config.target_cmd.empty()) {
        fuzzer.setExecutionCallback([&config](const std::vector<uint8_t>& input) {
            return executeTarget(config.target_cmd, input, config.timeout_us);
        });
    } else {
        fuzzer.setExecutionCallback(simulateTarget);
    }
    
    // Set up progress callback
    fuzzer.setProgressCallback([&config](const FuzzerStats& stats) {
        auto elapsed = std::chrono::steady_clock::now() - stats.start_time;
        
        std::cout << "\r[" << formatDuration(elapsed) << "] "
                  << "Execs: " << stats.total_executions 
                  << " (" << std::fixed << std::setprecision(0) << stats.execs_per_second << "/s) | "
                  << "Crashes: " << stats.crashes_found 
                  << " | Corpus: " << stats.corpus_size
                  << "          " << std::flush;
    });
    
    // Set up crash callback
    fuzzer.setCrashCallback([&config](const CrashInfo& crash) {
        std::cout << "\n[CRASH] Found at exec #" << crash.execution_count << "\n";
        std::cout << "  Type: " << crash.crash_type << "\n";
        std::cout << "  Input: " << formatBytes(crash.input, 32) << "\n";
    });
    
    // Load seeds
    if (!config.corpus_dir.empty()) {
        size_t loaded = fuzzer.loadSeedsFromDirectory(config.corpus_dir);
        if (config.verbose) {
            std::cout << "Loaded " << loaded << " seeds from corpus\n";
        }
    }
    
    // Add default seeds if no corpus
    if (fuzzer.getStats().corpus_size == 0) {
        // Add valid protocol messages as seeds
        auto handshake = ProtocolCodec::createHandshake(1, 0x0F);
        auto data = ProtocolCodec::createDataMessage({0x01, 0x02, 0x03, 0x04}, 1);
        auto heartbeat = ProtocolCodec::createHeartbeat(12345);
        
        fuzzer.addSeed(handshake);
        fuzzer.addSeed(data);
        fuzzer.addSeed(heartbeat);
        
        if (config.verbose) {
            std::cout << "Added default seed messages\n";
        }
    }
    
    // Create output directories
    if (!config.output_dir.empty()) {
        ensureDirectory(config.output_dir);
        ensureDirectory(config.output_dir + "/corpus");
        ensureDirectory(config.output_dir + "/crashes");
    }
    
    std::cout << "Starting fuzzer...\n";
    std::cout << "  Seed: " << (config.seed != 0 ? std::to_string(config.seed) : "random") << "\n";
    std::cout << "  Corpus: " << config.corpus_dir << "\n";
    std::cout << "  Output: " << config.output_dir << "\n";
    std::cout << "  Max iterations: " << (config.max_iterations != 0 ? 
                        std::to_string(config.max_iterations) : "unlimited") << "\n";
    std::cout << "\n";
    
    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGCHLD, cleanupChild);
    
    // Run fuzzer
    fuzzer.run(config.max_iterations);
    
    // Final statistics
    FuzzerStats stats = fuzzer.getStats();
    auto total_time = std::chrono::steady_clock::now() - stats.start_time;
    
    std::cout << "\n\nFuzzing complete!\n";
    std::cout << "  Total time: " << formatDuration(total_time) << "\n";
    std::cout << "  Total executions: " << stats.total_executions << "\n";
    std::cout << "  Executions/second: " << std::fixed << std::setprecision(1) 
              << stats.execs_per_second << "\n";
    std::cout << "  Crashes found: " << stats.crashes_found << "\n";
    std::cout << "  Corpus size: " << stats.corpus_size << "\n";

    if (!config.output_dir.empty()) {
        std::cout << "\nCorpus saved to: " << config.output_dir << "/corpus/\n";
    }

    if (stats.crashes_found > 0) {
        std::cout << "Crashes saved to: " << config.output_dir << "/crashes/\n";
    }
}

void generateSampleInput(const std::string& type) {
    std::vector<uint8_t> data;
    
    if (type == "handshake") {
        data = ProtocolCodec::createHandshake(1, 0x0F);
        std::cout << "Handshake message (" << data.size() << " bytes):\n";
    } else if (type == "data") {
        data = ProtocolCodec::createDataMessage({0xDE, 0xAD, 0xBE, 0xEF}, 42);
        std::cout << "Data message (" << data.size() << " bytes):\n";
    } else if (type == "heartbeat") {
        data = ProtocolCodec::createHeartbeat(1234567890);
        std::cout << "Heartbeat message (" << data.size() << " bytes):\n";
    } else {
        std::cerr << "Unknown input type: " << type << "\n";
        std::cerr << "Valid types: handshake, data, heartbeat\n";
        exit(1);
    }
    
    std::cout << "Hex: " << formatBytes(data) << "\n";
    std::cout << "Raw: ";
    for (uint8_t b : data) {
        std::cout << b << " ";
    }
    std::cout << "\n";
}

int parseOptions(int argc, char* argv[], Config& config) {
    static struct option long_options[] = {
        {"corpus",         required_argument, 0, 'c'},
        {"output",         required_argument, 0, 'o'},
        {"target",         required_argument, 0, 't'},
        {"seed",           required_argument, 0, 's'},
        {"iterations",     required_argument, 0, 'n'},
        {"timeout",        required_argument, 0, 'T'},
        {"max-size",       required_argument, 0, 'M'},
        {"min-size",       required_argument, 0, 'm'},
        {"mutations",      required_argument, 0, 'p'},
        {"generate",       required_argument, 0, 'g'},
        {"list-strategies", no_argument,      0, 'l'},
        {"verbose",        no_argument,       0, 'v'},
        {"dry-run",        no_argument,       0, 'd'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:o:t:s:n:T:M:m:p:g:lvhd", 
                              long_options, nullptr)) != -1) {
        switch (opt) {
            case 'c':
                config.corpus_dir = optarg;
                break;
            case 'o':
                config.output_dir = optarg;
                break;
            case 't':
                config.target_cmd = optarg;
                break;
            case 's':
                config.seed = static_cast<uint32_t>(std::stoul(optarg));
                break;
            case 'n':
                config.max_iterations = std::stoull(optarg);
                break;
            case 'T':
                config.timeout_us = std::stoull(optarg);
                break;
            case 'M':
                config.max_input_size = std::stoul(optarg);
                break;
            case 'm':
                config.min_input_size = std::stoul(optarg);
                break;
            case 'p':
                config.mutations_per_input = std::stoul(optarg);
                break;
            case 'g':
                config.generate_input = optarg;
                break;
            case 'l':
                config.list_strategies = true;
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'd':
                config.dry_run = true;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    return -1; // Continue with execution
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    Config config;
    
    int parse_result = parseOptions(argc, argv, config);
    if (parse_result == 0) {
        return 0;
    } else if (parse_result == 1) {
        return 1;
    }
    
    if (config.list_strategies) {
        printStrategies();
        return 0;
    }
    
    if (!config.generate_input.empty()) {
        generateSampleInput(config.generate_input);
        return 0;
    }
    
    if (config.dry_run) {
        std::cout << "Dry run - configuration test\n";
        std::cout << "  Corpus: " << config.corpus_dir << "\n";
        std::cout << "  Output: " << config.output_dir << "\n";
        std::cout << "  Target: " << (config.target_cmd.empty() ? "(simulated)" : config.target_cmd) << "\n";
        std::cout << "  Seed: " << config.seed << "\n";
        std::cout << "  Iterations: " << config.max_iterations << "\n";
        std::cout << "\nConfiguration OK\n";
        return 0;
    }
    
    try {
        runFuzzer(config);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
