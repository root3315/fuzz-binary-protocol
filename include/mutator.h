#ifndef MUTATOR_H
#define MUTATOR_H

#include <cstdint>
#include <vector>
#include <random>
#include <functional>
#include <string>
#include <memory>

namespace fuzzproto {

// Mutation strategy types
enum class MutationType {
    BIT_FLIP,
    BYTE_FLIP,
    BYTE_INSERT,
    BYTE_REMOVE,
    BYTE_DUPLICATE,
    ARITHMETIC_ADD,
    ARITHMETIC_SUB,
    INTERESTING_VALUE,
    BLOCK_INSERT,
    BLOCK_REMOVE,
    BLOCK_DUPLICATE,
    SHUFFLE_BYTES,
    MAGIC_BYTES,
    BOUNDARY_VALUE
};

// Mutation result structure
struct MutationResult {
    std::vector<uint8_t> mutated_data;
    MutationType type;
    size_t position;
    std::string description;
    bool success;
};

// Interesting values for fuzzing
struct InterestingValues {
    static const std::vector<int8_t> int8_values;
    static const std::vector<int16_t> int16_values;
    static const std::vector<int32_t> int32_values;
    static const std::vector<uint8_t> magic_bytes;
};

// Random number generator wrapper
class RandomGenerator {
public:
    RandomGenerator(uint32_t seed = 0);
    ~RandomGenerator() = default;

    uint32_t nextInt(uint32_t min, uint32_t max);
    size_t nextSize(size_t min, size_t max);
    uint8_t nextByte();
    double nextDouble();
    size_t chooseIndex(size_t size);
    template<typename T>
    T chooseFromVector(const std::vector<T>& vec);

private:
    std::mt19937 m_rng;
};

// Template implementation must be in header
template<typename T>
inline T RandomGenerator::chooseFromVector(const std::vector<T>& vec) {
    if (vec.empty()) return T{};
    return vec[chooseIndex(vec.size())];
}

// Base mutation strategy
class MutationStrategy {
public:
    virtual ~MutationStrategy() = default;
    virtual MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) = 0;
    virtual std::string name() const = 0;
    virtual double weight() const { return 1.0; }
};

// Bit flip mutation - flips random bits
class BitFlipStrategy : public MutationStrategy {
public:
    BitFlipStrategy(size_t num_bits = 1);
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "BitFlip"; }

private:
    size_t m_num_bits;
};

// Byte flip mutation - replaces byte with random value
class ByteFlipStrategy : public MutationStrategy {
public:
    ByteFlipStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "ByteFlip"; }
};

// Byte insert mutation - inserts random byte
class ByteInsertStrategy : public MutationStrategy {
public:
    ByteInsertStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "ByteInsert"; }
};

// Byte remove mutation - removes a byte
class ByteRemoveStrategy : public MutationStrategy {
public:
    ByteRemoveStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "ByteRemove"; }
};

// Byte duplicate mutation - duplicates a byte
class ByteDuplicateStrategy : public MutationStrategy {
public:
    ByteDuplicateStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "ByteDuplicate"; }
};

// Arithmetic mutation - adds/subtracts from value
class ArithmeticStrategy : public MutationStrategy {
public:
    ArithmeticStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "Arithmetic"; }

private:
    std::vector<int16_t> m_arithmetic_values;
};

// Interesting value insertion
class InterestingValueStrategy : public MutationStrategy {
public:
    InterestingValueStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "InterestingValue"; }
    double weight() const override { return 2.0; }
};

// Block operations - insert, remove, duplicate blocks
class BlockInsertStrategy : public MutationStrategy {
public:
    BlockInsertStrategy(size_t min_size = 1, size_t max_size = 64);
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "BlockInsert"; }

private:
    size_t m_min_size;
    size_t m_max_size;
};

class BlockRemoveStrategy : public MutationStrategy {
public:
    BlockRemoveStrategy(size_t min_size = 1, size_t max_size = 32);
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "BlockRemove"; }

private:
    size_t m_min_size;
    size_t m_max_size;
};

class BlockDuplicateStrategy : public MutationStrategy {
public:
    BlockDuplicateStrategy(size_t min_size = 1, size_t max_size = 32);
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "BlockDuplicate"; }

private:
    size_t m_min_size;
    size_t m_max_size;
};

// Shuffle bytes within a region
class ShuffleBytesStrategy : public MutationStrategy {
public:
    ShuffleBytesStrategy(size_t min_size = 2, size_t max_size = 16);
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "ShuffleBytes"; }

private:
    size_t m_min_size;
    size_t m_max_size;
};

// Magic bytes insertion (protocol-specific patterns)
class MagicBytesStrategy : public MutationStrategy {
public:
    MagicBytesStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "MagicBytes"; }
    double weight() const override { return 1.5; }
};

// Boundary value testing
class BoundaryValueStrategy : public MutationStrategy {
public:
    BoundaryValueStrategy();
    MutationResult mutate(const std::vector<uint8_t>& input, RandomGenerator& rng) override;
    std::string name() const override { return "BoundaryValue"; }
    double weight() const override { return 2.0; }
};

// Mutator engine - manages and applies mutations
class MutatorEngine {
public:
    MutatorEngine(uint32_t seed = 0);
    ~MutatorEngine() = default;
    
    // Delete copy operations (unique_ptr members)
    MutatorEngine(const MutatorEngine&) = delete;
    MutatorEngine& operator=(const MutatorEngine&) = delete;
    
    // Move operations
    MutatorEngine(MutatorEngine&&) = default;
    MutatorEngine& operator=(MutatorEngine&&) = default;

    // Apply a single mutation
    MutationResult applyMutation(const std::vector<uint8_t>& input);

    // Apply multiple mutations
    std::vector<MutationResult> applyMutations(const std::vector<uint8_t>& input, size_t count);

    // Add a custom strategy
    void addStrategy(std::unique_ptr<MutationStrategy> strategy);

    // Remove all strategies and reset to defaults
    void resetStrategies();

    // Get strategy by name
    MutationStrategy* getStrategy(const std::string& name);

    // Get all strategy names
    std::vector<std::string> getStrategyNames() const;

    // Enable/disable a strategy
    void setStrategyEnabled(const std::string& name, bool enabled);

    // Set mutation rate (0.0 to 1.0)
    void setMutationRate(double rate);

private:
    std::vector<std::unique_ptr<MutationStrategy>> m_strategies;
    std::vector<bool> m_enabled;
    RandomGenerator m_rng;
    double m_mutation_rate;

    void initializeDefaultStrategies();
    size_t selectStrategy();
};

} // namespace fuzzproto

#endif // MUTATOR_H
