#include "mutator.h"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <memory>

namespace fuzzproto {

// Interesting values initialization
const std::vector<int8_t> InterestingValues::int8_values = {
    -128, -100, -50, -10, -1, 0, 1, 10, 50, 100, 127
};

const std::vector<int16_t> InterestingValues::int16_values = {
    -32768, -1000, -500, -100, -1, 0, 1, 100, 500, 1000, 32767,
    256, 1, 32767, -32768, -1
};

const std::vector<int32_t> InterestingValues::int32_values = {
    -2147483647 - 1, -1000000, -65536, -1000, -1, 0, 1, 1000, 65536, 1000000,
    2147483647, 16777216, 65536, 256, 1,
    2147483647, -2147483647 - 1, -1
};

const std::vector<uint8_t> InterestingValues::magic_bytes = {
    0x00, 0x01, 0x7F, 0x80, 0xFF,
    0xBE, 0xEF, 0xDE, 0xAD, 0xCA, 0xFE, 0xBA, 0xBE
};

// RandomGenerator implementation
RandomGenerator::RandomGenerator(uint32_t seed) {
    if (seed == 0) {
        seed = static_cast<uint32_t>(std::random_device{}());
    }
    m_rng.seed(seed);
}

uint32_t RandomGenerator::nextInt(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    std::uniform_int_distribution<uint32_t> dist(min, max);
    return dist(m_rng);
}

size_t RandomGenerator::nextSize(size_t min, size_t max) {
    if (min >= max) return min;
    std::uniform_int_distribution<size_t> dist(min, max);
    return dist(m_rng);
}

uint8_t RandomGenerator::nextByte() {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    return static_cast<uint8_t>(dist(m_rng));
}

double RandomGenerator::nextDouble() {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(m_rng);
}

size_t RandomGenerator::chooseIndex(size_t size) {
    if (size == 0) return 0;
    return nextInt(0, static_cast<uint32_t>(size - 1));
}

// BitFlipStrategy implementation
BitFlipStrategy::BitFlipStrategy(size_t num_bits) : m_num_bits(num_bits) {}

MutationResult BitFlipStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BIT_FLIP;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input, cannot flip bits";
        return result;
    }

    result.mutated_data = input;
    size_t flips = rng.nextInt(1, static_cast<uint32_t>(m_num_bits));
    std::ostringstream desc;
    desc << "Flipped " << flips << " bit(s)";

    for (size_t i = 0; i < flips; ++i) {
        size_t byte_idx = rng.chooseIndex(result.mutated_data.size());
        uint8_t bit_mask = static_cast<uint8_t>(1 << rng.nextInt(0, 7));
        result.mutated_data[byte_idx] ^= bit_mask;
        result.position = byte_idx;
        desc << " at byte " << byte_idx;
    }

    result.description = desc.str();
    result.success = true;
    return result;
}

// ByteFlipStrategy implementation
ByteFlipStrategy::ByteFlipStrategy() {}

MutationResult ByteFlipStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BYTE_FLIP;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input, cannot flip byte";
        return result;
    }

    result.mutated_data = input;
    result.position = rng.chooseIndex(result.mutated_data.size());
    uint8_t old_value = result.mutated_data[result.position];
    result.mutated_data[result.position] = rng.nextByte();

    std::ostringstream desc;
    desc << "Flipped byte at position " << result.position;
    desc << " from 0x" << std::hex << static_cast<int>(old_value);
    desc << " to 0x" << std::hex << static_cast<int>(result.mutated_data[result.position]);
    result.description = desc.str();
    result.success = true;
    return result;
}

// ByteInsertStrategy implementation
ByteInsertStrategy::ByteInsertStrategy() {}

MutationResult ByteInsertStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BYTE_INSERT;
    result.success = false;

    result.mutated_data = input;
    size_t pos = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size()));
    uint8_t value = rng.nextByte();
    
    result.mutated_data.insert(result.mutated_data.begin() + pos, value);
    result.position = pos;

    std::ostringstream desc;
    desc << "Inserted byte 0x" << std::hex << static_cast<int>(value);
    desc << " at position " << pos;
    result.description = desc.str();
    result.success = true;
    return result;
}

// ByteRemoveStrategy implementation
ByteRemoveStrategy::ByteRemoveStrategy() {}

MutationResult ByteRemoveStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BYTE_REMOVE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input, cannot remove byte";
        return result;
    }

    result.mutated_data = input;
    result.position = rng.chooseIndex(result.mutated_data.size());
    uint8_t removed = result.mutated_data[result.position];
    result.mutated_data.erase(result.mutated_data.begin() + result.position);

    std::ostringstream desc;
    desc << "Removed byte 0x" << std::hex << static_cast<int>(removed);
    desc << " from position " << result.position;
    result.description = desc.str();
    result.success = true;
    return result;
}

// ByteDuplicateStrategy implementation
ByteDuplicateStrategy::ByteDuplicateStrategy() {}

MutationResult ByteDuplicateStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BYTE_DUPLICATE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input, cannot duplicate byte";
        return result;
    }

    result.mutated_data = input;
    result.position = rng.chooseIndex(result.mutated_data.size());
    uint8_t value = result.mutated_data[result.position];
    
    size_t insert_pos = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size()));
    result.mutated_data.insert(result.mutated_data.begin() + insert_pos, value);

    std::ostringstream desc;
    desc << "Duplicated byte 0x" << std::hex << static_cast<int>(value);
    desc << " from position " << result.position << " to position " << insert_pos;
    result.description = desc.str();
    result.success = true;
    return result;
}

// ArithmeticStrategy implementation
ArithmeticStrategy::ArithmeticStrategy()
    : m_arithmetic_values{-1000, -100, -10, -1, 1, 10, 100, 1000,
                          32767, -32768, 0, 0} {}

MutationResult ArithmeticStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::ARITHMETIC_ADD;
    result.success = false;

    if (input.size() < 2) {
        result.description = "Input too small for arithmetic mutation";
        return result;
    }

    result.mutated_data = input;
    
    // Choose between 16-bit and 32-bit operations
    bool is_32bit = rng.nextDouble() < 0.3 && input.size() >= 4;
    size_t pos = rng.nextInt(0, static_cast<uint32_t>(input.size() - (is_32bit ? 4 : 2)));
    result.position = pos;

    int16_t delta = m_arithmetic_values[rng.chooseIndex(m_arithmetic_values.size())];
    if (rng.nextDouble() < 0.5) {
        result.type = MutationType::ARITHMETIC_SUB;
        delta = -delta;
    }

    if (is_32bit) {
        uint32_t value = static_cast<uint32_t>(result.mutated_data[pos]) << 24 |
                        static_cast<uint32_t>(result.mutated_data[pos + 1]) << 16 |
                        static_cast<uint32_t>(result.mutated_data[pos + 2]) << 8 |
                        static_cast<uint32_t>(result.mutated_data[pos + 3]);
        value = static_cast<uint32_t>(static_cast<int32_t>(value) + delta);
        result.mutated_data[pos] = static_cast<uint8_t>((value >> 24) & 0xFF);
        result.mutated_data[pos + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        result.mutated_data[pos + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        result.mutated_data[pos + 3] = static_cast<uint8_t>(value & 0xFF);
    } else {
        uint16_t value = static_cast<uint16_t>(result.mutated_data[pos]) << 8 |
                        static_cast<uint16_t>(result.mutated_data[pos + 1]);
        value = static_cast<uint16_t>(static_cast<int16_t>(value) + delta);
        result.mutated_data[pos] = static_cast<uint8_t>((value >> 8) & 0xFF);
        result.mutated_data[pos + 1] = static_cast<uint8_t>(value & 0xFF);
    }

    std::ostringstream desc;
    desc << "Applied arithmetic " << (result.type == MutationType::ARITHMETIC_ADD ? "+" : "-");
    desc << std::abs(delta) << " at position " << pos;
    result.description = desc.str();
    result.success = true;
    return result;
}

// InterestingValueStrategy implementation
InterestingValueStrategy::InterestingValueStrategy() {}

MutationResult InterestingValueStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::INTERESTING_VALUE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input";
        return result;
    }

    result.mutated_data = input;
    
    // Choose value size
    double choice = rng.nextDouble();
    size_t value_size;
    
    if (choice < 0.4) {
        value_size = 1;
    } else if (choice < 0.7) {
        value_size = 2;
    } else {
        value_size = 4;
    }

    if (input.size() < value_size) {
        value_size = input.size();
    }

    result.position = rng.nextInt(0, static_cast<uint32_t>(input.size() - value_size + 1));

    std::ostringstream desc;
    desc << "Inserted interesting value at position " << result.position << ": ";

    if (value_size == 1) {
        uint8_t val = InterestingValues::magic_bytes[rng.chooseIndex(InterestingValues::magic_bytes.size())];
        result.mutated_data[result.position] = val;
        desc << "0x" << std::hex << static_cast<int>(val);
    } else if (value_size == 2) {
        int16_t val = InterestingValues::int16_values[rng.chooseIndex(InterestingValues::int16_values.size())];
        result.mutated_data[result.position] = static_cast<uint8_t>((val >> 8) & 0xFF);
        result.mutated_data[result.position + 1] = static_cast<uint8_t>(val & 0xFF);
        desc << "0x" << std::hex << static_cast<uint16_t>(val);
    } else {
        int32_t val = InterestingValues::int32_values[rng.chooseIndex(InterestingValues::int32_values.size())];
        result.mutated_data[result.position] = static_cast<uint8_t>((val >> 24) & 0xFF);
        result.mutated_data[result.position + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
        result.mutated_data[result.position + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
        result.mutated_data[result.position + 3] = static_cast<uint8_t>(val & 0xFF);
        desc << "0x" << std::hex << static_cast<uint32_t>(val);
    }

    result.description = desc.str();
    result.success = true;
    return result;
}

// BlockInsertStrategy implementation
BlockInsertStrategy::BlockInsertStrategy(size_t min_size, size_t max_size)
    : m_min_size(min_size), m_max_size(max_size) {}

MutationResult BlockInsertStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BLOCK_INSERT;
    result.success = false;

    size_t block_size = rng.nextSize(m_min_size, m_max_size);
    std::vector<uint8_t> block(block_size);
    
    for (size_t i = 0; i < block_size; ++i) {
        block[i] = rng.nextByte();
    }

    result.mutated_data = input;
    size_t pos = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size()));
    result.mutated_data.insert(result.mutated_data.begin() + pos, block.begin(), block.end());
    result.position = pos;

    std::ostringstream desc;
    desc << "Inserted " << block_size << "-byte block at position " << pos;
    result.description = desc.str();
    result.success = true;
    return result;
}

// BlockRemoveStrategy implementation
BlockRemoveStrategy::BlockRemoveStrategy(size_t min_size, size_t max_size)
    : m_min_size(min_size), m_max_size(max_size) {}

MutationResult BlockRemoveStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BLOCK_REMOVE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input";
        return result;
    }

    size_t max_block = std::min(m_max_size, input.size());
    if (max_block < m_min_size) {
        result.description = "Input too small for block removal";
        return result;
    }

    size_t block_size = rng.nextSize(m_min_size, max_block);
    result.mutated_data = input;
    result.position = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size() - block_size + 1));
    
    result.mutated_data.erase(result.mutated_data.begin() + result.position,
                              result.mutated_data.begin() + result.position + block_size);

    std::ostringstream desc;
    desc << "Removed " << block_size << "-byte block from position " << result.position;
    result.description = desc.str();
    result.success = true;
    return result;
}

// BlockDuplicateStrategy implementation
BlockDuplicateStrategy::BlockDuplicateStrategy(size_t min_size, size_t max_size)
    : m_min_size(min_size), m_max_size(max_size) {}

MutationResult BlockDuplicateStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BLOCK_DUPLICATE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input";
        return result;
    }

    size_t max_block = std::min(m_max_size, input.size());
    if (max_block < m_min_size) {
        result.description = "Input too small for block duplication";
        return result;
    }

    size_t block_size = rng.nextSize(m_min_size, max_block);
    result.mutated_data = input;
    result.position = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size() - block_size + 1));
    
    std::vector<uint8_t> block(
        result.mutated_data.begin() + result.position,
        result.mutated_data.begin() + result.position + block_size
    );

    size_t insert_pos = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size()));
    result.mutated_data.insert(result.mutated_data.begin() + insert_pos, block.begin(), block.end());

    std::ostringstream desc;
    desc << "Duplicated " << block_size << "-byte block from position " << result.position;
    desc << " to position " << insert_pos;
    result.description = desc.str();
    result.success = true;
    return result;
}

// ShuffleBytesStrategy implementation
ShuffleBytesStrategy::ShuffleBytesStrategy(size_t min_size, size_t max_size)
    : m_min_size(min_size), m_max_size(max_size) {}

MutationResult ShuffleBytesStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::SHUFFLE_BYTES;
    result.success = false;

    if (input.size() < 2) {
        result.description = "Input too small for shuffle";
        return result;
    }

    size_t max_shuffle = std::min(m_max_size, input.size());
    size_t shuffle_size = rng.nextSize(m_min_size, max_shuffle);
    
    result.mutated_data = input;
    result.position = rng.nextInt(0, static_cast<uint32_t>(result.mutated_data.size() - shuffle_size + 1));

    // Fisher-Yates shuffle on the selected region
    for (size_t i = shuffle_size - 1; i > 0; --i) {
        size_t j = rng.nextInt(0, static_cast<uint32_t>(i));
        std::swap(result.mutated_data[result.position + i], 
                  result.mutated_data[result.position + j]);
    }

    std::ostringstream desc;
    desc << "Shuffled " << shuffle_size << " bytes starting at position " << result.position;
    result.description = desc.str();
    result.success = true;
    return result;
}

// MagicBytesStrategy implementation
MagicBytesStrategy::MagicBytesStrategy() {}

MutationResult MagicBytesStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::MAGIC_BYTES;
    result.success = false;

    if (input.size() < 2) {
        result.description = "Input too small";
        return result;
    }

    result.mutated_data = input;
    
    // Common magic byte sequences
    static const std::vector<std::vector<uint8_t>> magic_sequences = {
        {0xDE, 0xAD, 0xBE, 0xEF},
        {0xCA, 0xFE, 0xBA, 0xBE},
        {0xFE, 0xED, 0xFA, 0xCE},
        {0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF},
        {0xBE, 0xEF},
        {0x4D, 0x5A},  // MZ (DOS/PE)
        {0x7F, 0x45, 0x4C, 0x46},  // ELF
        {0x89, 0x50, 0x4E, 0x47},  // PNG
        {0x25, 0x50, 0x44, 0x46},  // PDF
    };

    const auto& sequence = magic_sequences[rng.chooseIndex(magic_sequences.size())];
    result.position = rng.nextInt(0, static_cast<uint32_t>(input.size() - sequence.size() + 1));

    for (size_t i = 0; i < sequence.size(); ++i) {
        result.mutated_data[result.position + i] = sequence[i];
    }

    std::ostringstream desc;
    desc << "Inserted magic bytes at position " << result.position << ": ";
    for (uint8_t b : sequence) {
        desc << std::hex << static_cast<int>(b) << " ";
    }
    result.description = desc.str();
    result.success = true;
    return result;
}

// BoundaryValueStrategy implementation
BoundaryValueStrategy::BoundaryValueStrategy() {}

MutationResult BoundaryValueStrategy::mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) {
    MutationResult result;
    result.type = MutationType::BOUNDARY_VALUE;
    result.success = false;

    if (input.empty()) {
        result.description = "Empty input";
        return result;
    }

    result.mutated_data = input;
    
    // Boundary values to test
    static const std::vector<uint8_t> boundaries = {
        0x00, 0x01, 0x7F, 0x80, 0xFF,
        0x0F, 0xF0, 0x10, 0xEF
    };

    result.position = rng.chooseIndex(result.mutated_data.size());
    uint8_t boundary = boundaries[rng.chooseIndex(boundaries.size())];
    result.mutated_data[result.position] = boundary;

    std::ostringstream desc;
    desc << "Set boundary value 0x" << std::hex << static_cast<int>(boundary);
    desc << " at position " << result.position;
    result.description = desc.str();
    result.success = true;
    return result;
}

// MutatorEngine implementation
MutatorEngine::MutatorEngine(uint32_t seed) 
    : m_rng(seed), m_mutation_rate(1.0) {
    initializeDefaultStrategies();
}

void MutatorEngine::initializeDefaultStrategies() {
    m_strategies.clear();
    m_enabled.clear();

    m_strategies.push_back(std::make_unique<BitFlipStrategy>(4));
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ByteFlipStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ByteInsertStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ByteRemoveStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ByteDuplicateStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ArithmeticStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<InterestingValueStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<BlockInsertStrategy>(1, 32));
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<BlockRemoveStrategy>(1, 16));
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<BlockDuplicateStrategy>(1, 16));
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<ShuffleBytesStrategy>(2, 8));
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<MagicBytesStrategy>());
    m_enabled.push_back(true);

    m_strategies.push_back(std::make_unique<BoundaryValueStrategy>());
    m_enabled.push_back(true);
}

MutationResult MutatorEngine::applyMutation(const std::vector<uint8_t>& input) {
    if (input.empty()) {
        MutationResult result;
        result.success = false;
        result.description = "Empty input";
        return result;
    }

    size_t strategy_idx = selectStrategy();
    if (strategy_idx >= m_strategies.size()) {
        MutationResult result;
        result.success = false;
        result.description = "No strategies available";
        return result;
    }

    return m_strategies[strategy_idx]->mutate(input, m_rng);
}

std::vector<MutationResult> MutatorEngine::applyMutations(const std::vector<uint8_t>& input, size_t count) {
    std::vector<MutationResult> results;
    results.reserve(count);

    std::vector<uint8_t> current = input;
    for (size_t i = 0; i < count; ++i) {
        MutationResult result = applyMutation(current);
        if (result.success) {
            current = result.mutated_data;
            results.push_back(result);
        }
    }

    return results;
}

void MutatorEngine::addStrategy(std::unique_ptr<MutationStrategy> strategy) {
    m_strategies.push_back(std::move(strategy));
    m_enabled.push_back(true);
}

void MutatorEngine::resetStrategies() {
    initializeDefaultStrategies();
}

MutationStrategy* MutatorEngine::getStrategy(const std::string& name) {
    for (size_t i = 0; i < m_strategies.size(); ++i) {
        if (m_strategies[i]->name() == name && m_enabled[i]) {
            return m_strategies[i].get();
        }
    }
    return nullptr;
}

std::vector<std::string> MutatorEngine::getStrategyNames() const {
    std::vector<std::string> names;
    for (size_t i = 0; i < m_strategies.size(); ++i) {
        if (m_enabled[i]) {
            names.push_back(m_strategies[i]->name());
        }
    }
    return names;
}

void MutatorEngine::setStrategyEnabled(const std::string& name, bool enabled) {
    for (size_t i = 0; i < m_strategies.size(); ++i) {
        if (m_strategies[i]->name() == name) {
            m_enabled[i] = enabled;
            break;
        }
    }
}

void MutatorEngine::setMutationRate(double rate) {
    m_mutation_rate = std::max(0.0, std::min(1.0, rate));
}

size_t MutatorEngine::selectStrategy() {
    // Weighted random selection
    std::vector<double> weights;
    double total_weight = 0.0;

    for (size_t i = 0; i < m_strategies.size(); ++i) {
        if (m_enabled[i]) {
            double w = m_strategies[i]->weight();
            weights.push_back(w);
            total_weight += w;
        } else {
            weights.push_back(0.0);
        }
    }

    if (total_weight == 0.0) {
        return m_strategies.size(); // No valid strategies
    }

    double choice = m_rng.nextDouble() * total_weight;
    double cumulative = 0.0;

    for (size_t i = 0; i < weights.size(); ++i) {
        cumulative += weights[i];
        if (choice <= cumulative) {
            return i;
        }
    }

    return m_strategies.size() - 1;
}

} // namespace fuzzproto
