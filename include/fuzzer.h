#ifndef FUZZER_H
#define FUZZER_H

#include "protocol.h"
#include "mutator.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace fuzzproto {

// Execution result from target
struct ExecutionResult {
    enum Status {
        OK,
        CRASH,
        TIMEOUT,
        HANG,
        ERROR
    };

    Status status;
    uint64_t execution_time_us;
    std::vector<uint8_t> coverage;
    std::string error_message;
    int exit_code;
};

// Corpus entry
struct CorpusEntry {
    std::vector<uint8_t> data;
    uint64_t hash;
    size_t interesting_features;
    std::string source;
    std::chrono::system_clock::time_point added_time;
};

// Statistics for the fuzzer
struct FuzzerStats {
    uint64_t total_executions;
    uint64_t crashes_found;
    uint64_t timeouts_found;
    uint64_t unique_inputs;
    uint64_t corpus_size;
    uint64_t mutations_applied;
    double execs_per_second;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_update;
    
    // Per-strategy statistics
    std::unordered_map<std::string, uint64_t> strategy_stats;
    
    FuzzerStats() : total_executions(0), crashes_found(0), timeouts_found(0),
                    unique_inputs(0), corpus_size(0), mutations_applied(0),
                    execs_per_second(0.0), start_time(std::chrono::steady_clock::now()),
                    last_update(std::chrono::steady_clock::now()) {}
};

// Crash information
struct CrashInfo {
    std::vector<uint8_t> input;
    std::string crash_type;
    std::string stack_trace;
    uint64_t execution_count;
    std::chrono::system_clock::time_point found_time;
    bool minimized;
};

// Callback types
using ExecutionCallback = std::function<ExecutionResult(const std::vector<uint8_t>&)>;
using ProgressCallback = std::function<void(const FuzzerStats&)>;
using CrashCallback = std::function<void(const CrashInfo&)>;

// Fuzzer configuration
struct FuzzerConfig {
    uint32_t seed;
    size_t max_input_size;
    size_t min_input_size;
    uint64_t timeout_us;
    size_t max_corpus_size;
    size_t mutations_per_input;
    bool minimize_crashes;
    bool save_all_inputs;
    std::string output_dir;
    std::string corpus_dir;
    
    FuzzerConfig() 
        : seed(0), max_input_size(65535), min_input_size(8), timeout_us(1000000),
          max_corpus_size(10000), mutations_per_input(4), minimize_crashes(true),
          save_all_inputs(false) {}
};

// Coverage tracker
class CoverageTracker {
public:
    CoverageTracker();
    ~CoverageTracker() = default;

    // Check if coverage is new
    bool isNewCoverage(const std::vector<uint8_t>& coverage);

    // Add coverage to tracked set
    void addCoverage(const std::vector<uint8_t>& coverage);

    // Get coverage statistics
    size_t getTotalCoverage() const;
    size_t getUniqueEdges() const;

    // Calculate coverage hash
    static uint64_t hashCoverage(const std::vector<uint8_t>& coverage);

private:
    std::unordered_set<uint64_t> m_coverage_hashes;
    mutable std::mutex m_mutex;
};

// Corpus manager
class CorpusManager {
public:
    CorpusManager(size_t max_size = 10000);
    ~CorpusManager() = default;

    // Add input to corpus
    bool addInput(const std::vector<uint8_t>& data, const std::string& source = "unknown");

    // Get random input from corpus
    std::vector<uint8_t> getRandomInput();

    // Get input by index
    std::vector<uint8_t> getInput(size_t index);

    // Get corpus size
    size_t size() const;

    // Clear corpus
    void clear();

    // Get all inputs
    const std::vector<CorpusEntry>& entries() const { return m_entries; }

    // Save corpus to directory
    bool saveToDirectory(const std::string& dir) const;

    // Load corpus from directory
    bool loadFromDirectory(const std::string& dir);

private:
    std::vector<CorpusEntry> m_entries;
    std::unordered_set<uint64_t> m_input_hashes;
    size_t m_max_size;
    mutable std::mutex m_mutex;

    uint64_t hashInput(const std::vector<uint8_t>& data) const;
};

// Main fuzzer class
class Fuzzer {
public:
    explicit Fuzzer(const FuzzerConfig& config = FuzzerConfig());
    ~Fuzzer();
    
    // Delete copy operations (unique_ptr members in MutatorEngine)
    Fuzzer(const Fuzzer&) = delete;
    Fuzzer& operator=(const Fuzzer&) = delete;
    
    // Move operations
    Fuzzer(Fuzzer&&) = default;
    Fuzzer& operator=(Fuzzer&&) = default;

    // Set execution callback (required)
    void setExecutionCallback(ExecutionCallback callback);

    // Set progress callback (optional)
    void setProgressCallback(ProgressCallback callback);

    // Set crash callback (optional)
    void setCrashCallback(CrashCallback callback);

    // Add seed input to corpus
    bool addSeed(const std::vector<uint8_t>& data);
    bool addSeed(const std::string& hex_data);

    // Load seeds from directory
    size_t loadSeedsFromDirectory(const std::string& dir);

    // Run fuzzing loop
    void run(uint64_t max_iterations = 0);

    // Stop fuzzing
    void stop();

    // Check if running
    bool isRunning() const;

    // Get statistics
    FuzzerStats getStats() const;

    // Get configuration
    const FuzzerConfig& getConfig() const { return m_config; }

    // Get mutator engine
    MutatorEngine& getMutator() { return m_mutator; }

    // Get coverage tracker
    CoverageTracker& getCoverageTracker() { return m_coverage; }

    // Get found crashes
    const std::vector<CrashInfo>& getCrashes() const { return m_crashes; }

    // Generate a test input
    std::vector<uint8_t> generateInput();

    // Minimize a crash input
    std::vector<uint8_t> minimizeInput(const std::vector<uint8_t>& input);

    // Save crash to file
    bool saveCrash(const CrashInfo& crash);

    // Get status string
    std::string getStatusString() const;

private:
    FuzzerConfig m_config;
    MutatorEngine m_mutator;
    CorpusManager m_corpus;
    CoverageTracker m_coverage;
    
    ExecutionCallback m_exec_callback;
    ProgressCallback m_progress_callback;
    CrashCallback m_crash_callback;

    FuzzerStats m_stats;
    std::vector<CrashInfo> m_crashes;
    
    std::atomic<bool> m_running;
    std::atomic<bool> m_stop_requested;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;

    // Internal methods
    void fuzzIteration();
    ExecutionResult executeInput(const std::vector<uint8_t>& input);
    void handleCrash(const std::vector<uint8_t>& input, const ExecutionResult& result);
    void handleNewCoverage(const std::vector<uint8_t>& input, const std::vector<uint8_t>& coverage);
    void updateStats();
    void reportProgress();
    
    // Input generation strategies
    std::vector<uint8_t> generateFromCorpus();
    std::vector<uint8_t> generateFromMutation();
    std::vector<uint8_t> generateFreshInput();

    // Utility methods (public for use in FuzzCampaign)
    static uint64_t hashData(const std::vector<uint8_t>& data);
    static std::string bytesToHex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
};

// Helper class for creating fuzzing campaigns
class FuzzCampaign {
public:
    explicit FuzzCampaign(const std::string& name);
    ~FuzzCampaign() = default;

    FuzzCampaign& setSeed(uint32_t seed);
    FuzzCampaign& setMaxIterations(uint64_t iterations);
    FuzzCampaign& setTimeout(uint64_t timeout_us);
    FuzzCampaign& setOutputDir(const std::string& dir);
    FuzzCampaign& addSeed(const std::vector<uint8_t>& data);
    FuzzCampaign& addSeed(const std::string& hex_data);
    FuzzCampaign& loadSeeds(const std::string& dir);

    bool run(ExecutionCallback callback, ProgressCallback progress_cb = nullptr);

    FuzzerStats getStats() const { return m_stats; }
    std::string getName() const { return m_name; }

private:
    std::string m_name;
    FuzzerConfig m_config;
    std::vector<std::vector<uint8_t>> m_seeds;
    FuzzerStats m_stats;
};

} // namespace fuzzproto

#endif // FUZZER_H
