#include "fuzzer.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <sys/stat.h>

namespace fuzzproto {

// CoverageTracker implementation
CoverageTracker::CoverageTracker() {}

bool CoverageTracker::isNewCoverage(const std::vector<uint8_t>& coverage) {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t hash = hashCoverage(coverage);
    if (m_coverage_hashes.find(hash) == m_coverage_hashes.end()) {
        m_coverage_hashes.insert(hash);
        return true;
    }
    return false;
}

void CoverageTracker::addCoverage(const std::vector<uint8_t>& coverage) {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t hash = hashCoverage(coverage);
    m_coverage_hashes.insert(hash);
}

size_t CoverageTracker::getTotalCoverage() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_coverage_hashes.size();
}

size_t CoverageTracker::getUniqueEdges() const {
    return getTotalCoverage();
}

uint64_t CoverageTracker::hashCoverage(const std::vector<uint8_t>& coverage) {
    // Simple hash for coverage bitmap
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (uint8_t byte : coverage) {
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

// CorpusManager implementation
CorpusManager::CorpusManager(size_t max_size) : m_max_size(max_size) {}

bool CorpusManager::addInput(const std::vector<uint8_t>& data, const std::string& source) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (data.empty()) return false;
    
    uint64_t hash = hashInput(data);
    if (m_input_hashes.find(hash) != m_input_hashes.end()) {
        return false; // Duplicate
    }

    if (m_entries.size() >= m_max_size) {
        // Remove oldest entry
        m_input_hashes.erase(hashInput(m_entries.front().data));
        m_entries.erase(m_entries.begin());
    }

    CorpusEntry entry;
    entry.data = data;
    entry.hash = hash;
    entry.interesting_features = 0;
    entry.source = source;
    entry.added_time = std::chrono::system_clock::now();

    m_entries.push_back(entry);
    m_input_hashes.insert(hash);
    return true;
}

std::vector<uint8_t> CorpusManager::getRandomInput() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_entries.empty()) {
        return {};
    }

    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, m_entries.size() - 1);

    return m_entries[dist(gen)].data;
}

std::vector<uint8_t> CorpusManager::getInput(size_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (index >= m_entries.size()) {
        return {};
    }

    return m_entries[index].data;
}

size_t CorpusManager::size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

void CorpusManager::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.clear();
    m_input_hashes.clear();
}

bool CorpusManager::saveToDirectory(const std::string& dir) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    struct stat st;
    if (stat(dir.c_str(), &st) != 0) {
        mkdir(dir.c_str(), 0755);
    }

    for (size_t i = 0; i < m_entries.size(); ++i) {
        std::ostringstream filename;
        filename << dir << "/input_" << std::setfill('0') << std::setw(6) << i << ".bin";
        
        std::ofstream ofs(filename.str(), std::ios::binary);
        if (!ofs) {
            return false;
        }
        ofs.write(reinterpret_cast<const char*>(m_entries[i].data.data()), 
                  m_entries[i].data.size());
    }
    return true;
}

bool CorpusManager::loadFromDirectory(const std::string& dir) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    struct stat st;
    if (stat(dir.c_str(), &st) != 0) {
        return false;
    }

    // Simple directory loading - in production, use proper directory iteration
    for (int i = 0; i < 10000; ++i) {
        std::ostringstream filename;
        filename << dir << "/input_" << std::setfill('0') << std::setw(6) << i << ".bin";
        
        std::ifstream ifs(filename.str(), std::ios::binary | std::ios::ate);
        if (!ifs) {
            break;
        }

        std::streamsize size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(size);
        if (ifs.read(reinterpret_cast<char*>(buffer.data()), size)) {
            CorpusEntry entry;
            entry.data = buffer;
            entry.hash = hashInput(buffer);
            entry.source = "loaded";
            entry.added_time = std::chrono::system_clock::now();
            
            m_entries.push_back(entry);
            m_input_hashes.insert(entry.hash);
        }
    }
    return true;
}

uint64_t CorpusManager::hashInput(const std::vector<uint8_t>& data) const {
    return CoverageTracker::hashCoverage(data);
}

// Fuzzer implementation
Fuzzer::Fuzzer(const FuzzerConfig& config)
    : m_config(config), m_mutator(config.seed), m_corpus(config.max_corpus_size),
      m_running(false), m_stop_requested(false) {
    // m_mutator is already initialized with config.seed in the initializer list
}

Fuzzer::~Fuzzer() {
    stop();
}

void Fuzzer::setExecutionCallback(ExecutionCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_exec_callback = callback;
}

void Fuzzer::setProgressCallback(ProgressCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_progress_callback = callback;
}

void Fuzzer::setCrashCallback(CrashCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_crash_callback = callback;
}

bool Fuzzer::addSeed(const std::vector<uint8_t>& data) {
    if (data.empty() || data.size() < m_config.min_input_size) {
        return false;
    }
    return m_corpus.addInput(data, "seed");
}

bool Fuzzer::addSeed(const std::string& hex_data) {
    std::vector<uint8_t> data = hexToBytes(hex_data);
    return addSeed(data);
}

size_t Fuzzer::loadSeedsFromDirectory(const std::string& dir) {
    size_t count = m_corpus.size();
    m_corpus.loadFromDirectory(dir);
    return m_corpus.size() - count;
}

void Fuzzer::run(uint64_t max_iterations) {
    if (!m_exec_callback) {
        throw std::runtime_error("Execution callback not set");
    }

    m_running = true;
    m_stop_requested = false;
    m_stats.start_time = std::chrono::steady_clock::now();
    m_stats.last_update = m_stats.start_time;

    uint64_t iteration = 0;
    auto progress_interval = std::chrono::seconds(1);
    auto last_progress = std::chrono::steady_clock::now();

    while (!m_stop_requested) {
        if (max_iterations > 0 && iteration >= max_iterations) {
            break;
        }

        fuzzIteration();
        ++iteration;
        ++m_stats.total_executions;

        auto now = std::chrono::steady_clock::now();
        if (now - last_progress >= progress_interval) {
            updateStats();
            reportProgress();
            last_progress = now;
        }
    }

    m_running = false;
    updateStats();
    reportProgress();
}

void Fuzzer::stop() {
    m_stop_requested = true;
}

bool Fuzzer::isRunning() const {
    return m_running && !m_stop_requested;
}

FuzzerStats Fuzzer::getStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    FuzzerStats stats = m_stats;
    stats.corpus_size = m_corpus.size();
    stats.unique_inputs = m_corpus.size();
    stats.crashes_found = m_crashes.size();
    return stats;
}

std::vector<uint8_t> Fuzzer::generateInput() {
    if (m_corpus.size() == 0) {
        return generateFreshInput();
    }

    // 70% mutation, 20% corpus selection, 10% fresh
    double choice = static_cast<double>(rand()) / RAND_MAX;
    
    if (choice < 0.7) {
        return generateFromMutation();
    } else if (choice < 0.9) {
        return generateFromCorpus();
    } else {
        return generateFreshInput();
    }
}

std::vector<uint8_t> Fuzzer::generateFromCorpus() {
    return m_corpus.getRandomInput();
}

std::vector<uint8_t> Fuzzer::generateFromMutation() {
    std::vector<uint8_t> base = m_corpus.getRandomInput();
    if (base.empty()) {
        return generateFreshInput();
    }

    // Apply multiple mutations
    size_t num_mutations = m_config.mutations_per_input;
    for (size_t i = 0; i < num_mutations; ++i) {
        MutationResult result = m_mutator.applyMutation(base);
        if (result.success) {
            base = result.mutated_data;
            ++m_stats.mutations_applied;
            
            // Track strategy usage
            auto it = m_stats.strategy_stats.find(result.description.substr(0, 20));
            if (it == m_stats.strategy_stats.end()) {
                m_stats.strategy_stats[result.description.substr(0, 20)] = 1;
            } else {
                ++it->second;
            }
        }
    }

    // Enforce size limits
    if (base.size() > m_config.max_input_size) {
        base.resize(m_config.max_input_size);
    }

    return base;
}

std::vector<uint8_t> Fuzzer::generateFreshInput() {
    // Generate a valid protocol message
    size_t payload_size = m_config.min_input_size + (rand() % 64);
    std::vector<uint8_t> payload(payload_size);
    
    for (size_t i = 0; i < payload_size; ++i) {
        payload[i] = static_cast<uint8_t>(rand() % 256);
    }

    ProtocolCodec codec;
    MessageType types[] = {MessageType::HANDSHAKE, MessageType::DATA, 
                          MessageType::HEARTBEAT, MessageType::ACK};
    MessageType type = types[rand() % 4];
    
    return codec.encode(type, payload, static_cast<uint8_t>(rand() % 256),
                        static_cast<uint16_t>(rand() % 65536));
}

void Fuzzer::fuzzIteration() {
    std::vector<uint8_t> input = generateInput();
    ExecutionResult result = executeInput(input);

    switch (result.status) {
        case ExecutionResult::CRASH:
            handleCrash(input, result);
            break;
        case ExecutionResult::TIMEOUT:
        case ExecutionResult::HANG:
            ++m_stats.timeouts_found;
            break;
        case ExecutionResult::OK:
            if (!result.coverage.empty() && m_coverage.isNewCoverage(result.coverage)) {
                handleNewCoverage(input, result.coverage);
            }
            break;
        default:
            break;
    }
}

ExecutionResult Fuzzer::executeInput(const std::vector<uint8_t>& input) {
    if (!m_exec_callback) {
        ExecutionResult result;
        result.status = ExecutionResult::ERROR;
        result.error_message = "No execution callback";
        return result;
    }

    return m_exec_callback(input);
}

void Fuzzer::handleCrash(const std::vector<uint8_t>& input, const ExecutionResult& result) {
    CrashInfo crash;
    crash.input = input;
    crash.crash_type = result.error_message;
    crash.execution_count = m_stats.total_executions;
    crash.found_time = std::chrono::system_clock::now();
    crash.minimized = false;

    m_crashes.push_back(crash);

    if (m_crash_callback) {
        m_crash_callback(crash);
    }

    if (m_config.save_all_inputs || m_config.minimize_crashes) {
        saveCrash(crash);
    }
}

void Fuzzer::handleNewCoverage(const std::vector<uint8_t>& input, 
                                const std::vector<uint8_t>& coverage) {
    m_corpus.addInput(input, "coverage");
    m_coverage.addCoverage(coverage);
}

void Fuzzer::updateStats() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_stats.start_time).count();
    
    if (elapsed > 0) {
        m_stats.execs_per_second = static_cast<double>(m_stats.total_executions) / elapsed;
    }
    m_stats.last_update = now;
}

void Fuzzer::reportProgress() {
    if (m_progress_callback) {
        m_progress_callback(m_stats);
    }
}

std::vector<uint8_t> Fuzzer::minimizeInput(const std::vector<uint8_t>& input) {
    if (input.size() <= m_config.min_input_size) {
        return input;
    }

    std::vector<uint8_t> minimized = input;
    bool changed = true;

    while (changed && minimized.size() > m_config.min_input_size) {
        changed = false;
        
        // Try removing bytes from the end
        while (minimized.size() > m_config.min_input_size) {
            std::vector<uint8_t> test = minimized;
            test.pop_back();
            
            ExecutionResult result = executeInput(test);
            if (result.status == ExecutionResult::CRASH) {
                minimized = test;
                changed = true;
            } else {
                break;
            }
        }

        // Try removing bytes from the middle
        for (size_t i = 1; i < minimized.size() - 1 && 
             minimized.size() > m_config.min_input_size; ++i) {
            std::vector<uint8_t> test = minimized;
            test.erase(test.begin() + i);
            
            ExecutionResult result = executeInput(test);
            if (result.status == ExecutionResult::CRASH) {
                minimized = test;
                changed = true;
                break;
            }
        }
    }

    return minimized;
}

bool Fuzzer::saveCrash(const CrashInfo& crash) {
    if (m_config.output_dir.empty()) {
        return false;
    }

    struct stat st;
    if (stat(m_config.output_dir.c_str(), &st) != 0) {
        mkdir(m_config.output_dir.c_str(), 0755);
    }

    std::string crash_dir = m_config.output_dir + "/crashes";
    if (stat(crash_dir.c_str(), &st) != 0) {
        mkdir(crash_dir.c_str(), 0755);
    }

    std::ostringstream filename;
    filename << crash_dir << "/crash_" << crash.execution_count << "_"
             << bytesToHex(crash.input).substr(0, 8) << ".bin";

    std::ofstream ofs(filename.str(), std::ios::binary);
    if (!ofs) {
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(crash.input.data()), crash.input.size());
    return true;
}

std::string Fuzzer::getStatusString() const {
    std::ostringstream ss;
    ss << "Execs: " << m_stats.total_executions
       << " Crashes: " << m_crashes.size()
       << " Corpus: " << m_corpus.size()
       << " Coverage: " << m_coverage.getTotalCoverage()
       << " Exec/s: " << std::fixed << std::setprecision(1) << m_stats.execs_per_second;
    return ss.str();
}

uint64_t Fuzzer::hashData(const std::vector<uint8_t>& data) {
    return CoverageTracker::hashCoverage(data);
}

std::string Fuzzer::bytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> Fuzzer::hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// FuzzCampaign implementation
FuzzCampaign::FuzzCampaign(const std::string& name) : m_name(name) {}

FuzzCampaign& FuzzCampaign::setSeed(uint32_t seed) {
    m_config.seed = seed;
    return *this;
}

FuzzCampaign& FuzzCampaign::setMaxIterations(uint64_t iterations) {
    // Store in a way that can be used later
    return *this;
}

FuzzCampaign& FuzzCampaign::setTimeout(uint64_t timeout_us) {
    m_config.timeout_us = timeout_us;
    return *this;
}

FuzzCampaign& FuzzCampaign::setOutputDir(const std::string& dir) {
    m_config.output_dir = dir;
    return *this;
}

FuzzCampaign& FuzzCampaign::addSeed(const std::vector<uint8_t>& data) {
    m_seeds.push_back(data);
    return *this;
}

FuzzCampaign& FuzzCampaign::addSeed(const std::string& hex_data) {
    // Convert hex string to bytes
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex_data.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex_data.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    m_seeds.push_back(bytes);
    return *this;
}

FuzzCampaign& FuzzCampaign::loadSeeds(const std::string& dir) {
    CorpusManager temp_corpus;
    temp_corpus.loadFromDirectory(dir);
    
    for (size_t i = 0; i < temp_corpus.entries().size(); ++i) {
        m_seeds.push_back(temp_corpus.entries()[i].data);
    }
    return *this;
}

bool FuzzCampaign::run(ExecutionCallback callback, ProgressCallback progress_cb) {
    Fuzzer fuzzer(m_config);
    fuzzer.setExecutionCallback(callback);
    fuzzer.setProgressCallback(progress_cb);

    for (const auto& seed : m_seeds) {
        fuzzer.addSeed(seed);
    }

    if (!m_config.output_dir.empty()) {
        fuzzer.loadSeedsFromDirectory(m_config.output_dir + "/corpus");
    }

    fuzzer.run();
    m_stats = fuzzer.getStats();
    
    return true;
}

} // namespace fuzzproto
