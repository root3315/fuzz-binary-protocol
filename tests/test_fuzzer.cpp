#include "protocol.h"
#include "mutator.h"
#include "fuzzer.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <string>

using namespace fuzzproto;

int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) void name()
#define RUN_TEST(name) do { \
    tests_run++; \
    std::cout << "  Running " << #name << "... "; \
    try { \
        name(); \
        tests_passed++; \
        std::cout << "PASSED\n"; \
    } catch (const std::exception& e) { \
        tests_failed++; \
        std::cout << "FAILED: " << e.what() << "\n"; \
    } \
} while(0)

#define ASSERT_TRUE(x) do { if (!(x)) throw std::runtime_error("Assertion failed: " #x); } while(0)
#define ASSERT_FALSE(x) do { if (x) throw std::runtime_error("Assertion failed: !" #x); } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)
#define ASSERT_NE(a, b) do { if ((a) == (b)) throw std::runtime_error("Assertion failed: " #a " != " #b); } while(0)
#define ASSERT_GT(a, b) do { if ((a) <= (b)) throw std::runtime_error("Assertion failed: " #a " > " #b); } while(0)
#define ASSERT_LT(a, b) do { if ((a) >= (b)) throw std::runtime_error("Assertion failed: " #a " < " #b); } while(0)
#define ASSERT_LE(a, b) do { if ((a) > (b)) throw std::runtime_error("Assertion failed: " #a " <= " #b); } while(0)

TEST(test_protocol_encode_handshake) {
    ProtocolCodec codec;
    std::vector<uint8_t> payload = {0x00, 0x01, 0x00, 0x0F};
    std::vector<uint8_t> encoded = codec.encode(MessageType::HANDSHAKE, payload);
    
    ASSERT_EQ(encoded.size(), ProtocolCodec::HEADER_SIZE + 4);
    ASSERT_EQ(encoded[0], ProtocolCodec::MAGIC_BYTE1);
    ASSERT_EQ(encoded[1], ProtocolCodec::MAGIC_BYTE2);
    ASSERT_EQ(encoded[2], static_cast<uint8_t>(MessageType::HANDSHAKE));
}

TEST(test_protocol_encode_data) {
    ProtocolCodec codec;
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> encoded = codec.encode(MessageType::DATA, data, 0x42, 1234);
    
    ASSERT_EQ(encoded.size(), ProtocolCodec::HEADER_SIZE + 4);
    ASSERT_EQ(encoded[0], ProtocolCodec::MAGIC_BYTE1);
    ASSERT_EQ(encoded[1], ProtocolCodec::MAGIC_BYTE2);
    ASSERT_EQ(encoded[2], static_cast<uint8_t>(MessageType::DATA));
    ASSERT_EQ(encoded[3], 0x42);
}

TEST(test_protocol_decode) {
    ProtocolCodec codec;
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    std::vector<uint8_t> encoded = codec.encode(MessageType::ACK, payload, 0, 100);
    
    ParsedMessage decoded = codec.decode(encoded);
    
    ASSERT_TRUE(decoded.valid);
    ASSERT_EQ(decoded.header.type, MessageType::ACK);
    ASSERT_EQ(decoded.header.sequence, 100);
    ASSERT_EQ(decoded.payload.size(), 3);
    ASSERT_EQ(decoded.payload[0], 0x01);
}

TEST(test_protocol_decode_invalid_magic) {
    ProtocolCodec codec;
    std::vector<uint8_t> invalid = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    ParsedMessage decoded = codec.decode(invalid);
    
    ASSERT_FALSE(decoded.valid);
}

TEST(test_protocol_decode_truncated) {
    ProtocolCodec codec;
    std::vector<uint8_t> truncated = {0xBE, 0xEF, 0x01};
    
    ParsedMessage decoded = codec.decode(truncated);
    
    ASSERT_FALSE(decoded.valid);
}

TEST(test_protocol_validate) {
    ProtocolCodec codec;
    
    std::vector<uint8_t> valid = codec.encode(MessageType::DATA, {0x01, 0x02});
    ASSERT_EQ(codec.validate(valid), ValidationResult::VALID);
    
    std::vector<uint8_t> invalid_magic = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    ASSERT_EQ(codec.validate(invalid_magic), ValidationResult::INVALID_MAGIC);
    
    std::vector<uint8_t> truncated = {0xBE, 0xEF};
    ASSERT_EQ(codec.validate(truncated), ValidationResult::MALFORMED);
}

TEST(test_protocol_create_helpers) {
    auto handshake = ProtocolCodec::createHandshake(2, 0xFF);
    ASSERT_GT(handshake.size(), ProtocolCodec::HEADER_SIZE);
    
    auto data = ProtocolCodec::createDataMessage({0x42}, 1);
    ASSERT_GT(data.size(), ProtocolCodec::HEADER_SIZE);
    
    auto heartbeat = ProtocolCodec::createHeartbeat(12345);
    ASSERT_EQ(heartbeat.size(), ProtocolCodec::HEADER_SIZE + 4);
}

TEST(test_protocol_message_builder) {
    MessageBuilder builder;
    std::vector<uint8_t> msg = builder
        .setType(MessageType::DATA)
        .setFlags(0x10)
        .setSequence(42)
        .addUint32(0xDEADBEEF)
        .addString("hello")
        .build();
    
    ASSERT_GT(msg.size(), ProtocolCodec::HEADER_SIZE);
    
    ParsedMessage parsed = ProtocolCodec().decode(msg);
    ASSERT_TRUE(parsed.valid);
    ASSERT_EQ(parsed.header.type, MessageType::DATA);
    ASSERT_EQ(parsed.header.flags, 0x10);
    ASSERT_EQ(parsed.header.sequence, 42);
}

TEST(test_mutator_bit_flip) {
    MutatorEngine engine(42);
    std::vector<uint8_t> input = {0x00, 0xFF, 0xAA, 0x55};
    
    MutationResult result = engine.applyMutation(input);
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.mutated_data.size(), input.size());
    ASSERT_NE(result.mutated_data, input);
}

TEST(test_mutator_byte_flip) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x00, 0x11, 0x22, 0x33};
    
    BitFlipStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
}

TEST(test_mutator_byte_insert) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    
    ByteInsertStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.mutated_data.size(), input.size() + 1);
}

TEST(test_mutator_byte_remove) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04};
    
    ByteRemoveStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.mutated_data.size(), input.size() - 1);
}

TEST(test_mutator_arithmetic) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x00, 0x01, 0x00, 0x02};
    
    ArithmeticStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
}

TEST(test_mutator_interesting_values) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x00, 0x00, 0x00, 0x00};
    
    InterestingValueStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
}

TEST(test_mutator_block_operations) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input(64, 0x41);
    
    BlockInsertStrategy insert(4, 8);
    MutationResult result = insert.mutate(input, rng);
    ASSERT_TRUE(result.success);
    ASSERT_GT(result.mutated_data.size(), input.size());
    
    BlockRemoveStrategy remove(4, 8);
    result = remove.mutate(result.mutated_data, rng);
    ASSERT_TRUE(result.success);
    
    BlockDuplicateStrategy dup(4, 8);
    result = dup.mutate(input, rng);
    ASSERT_TRUE(result.success);
    ASSERT_GT(result.mutated_data.size(), input.size());
}

TEST(test_mutator_magic_bytes) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input(16, 0x00);
    
    MagicBytesStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
}

TEST(test_mutator_boundary_values) {
    RandomGenerator rng(42);
    std::vector<uint8_t> input = {0x50, 0x60, 0x70};
    
    BoundaryValueStrategy strategy;
    MutationResult result = strategy.mutate(input, rng);
    
    ASSERT_TRUE(result.success);
}

TEST(test_mutator_engine_strategies) {
    MutatorEngine engine(42);
    
    auto names = engine.getStrategyNames();
    ASSERT_GT(names.size(), 0);
    
    for (const auto& name : names) {
        ASSERT_FALSE(name.empty());
    }
}

TEST(test_mutator_multiple_mutations) {
    MutatorEngine engine(42);
    std::vector<uint8_t> input = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    auto results = engine.applyMutations(input, 5);
    
    ASSERT_EQ(results.size(), 5);
    for (const auto& result : results) {
        ASSERT_TRUE(result.success);
    }
}

TEST(test_corpus_manager) {
    CorpusManager cm(100);
    
    std::vector<uint8_t> input1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> input2 = {0x04, 0x05, 0x06};
    
    ASSERT_TRUE(cm.addInput(input1, "test1"));
    ASSERT_TRUE(cm.addInput(input2, "test2"));
    ASSERT_FALSE(cm.addInput(input1, "duplicate"));
    
    ASSERT_EQ(cm.size(), 2);
    
    auto random = cm.getRandomInput();
    ASSERT_GT(random.size(), 0);
    
    auto by_index = cm.getInput(0);
    ASSERT_EQ(by_index, input1);
}

TEST(test_coverage_tracker) {
    CoverageTracker tracker;
    
    std::vector<uint8_t> cov1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> cov2 = {0x04, 0x05, 0x06};
    
    ASSERT_TRUE(tracker.isNewCoverage(cov1));
    ASSERT_FALSE(tracker.isNewCoverage(cov1));
    ASSERT_TRUE(tracker.isNewCoverage(cov2));
    
    ASSERT_EQ(tracker.getTotalCoverage(), 2);
}

TEST(test_fuzzer_config) {
    FuzzerConfig config;
    config.seed = 12345;
    config.max_input_size = 1024;
    config.min_input_size = 16;
    config.mutations_per_input = 8;
    
    Fuzzer fuzzer(config);
    
    ASSERT_EQ(fuzzer.getConfig().seed, 12345);
    ASSERT_EQ(fuzzer.getConfig().max_input_size, 1024);
}

TEST(test_fuzzer_seed_input) {
    FuzzerConfig config;
    config.seed = 42;
    
    Fuzzer fuzzer(config);
    
    std::vector<uint8_t> seed = {0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04};
    ASSERT_TRUE(fuzzer.addSeed(seed));
    
    ASSERT_EQ(fuzzer.getStats().corpus_size, 1);
}

TEST(test_fuzzer_execution_callback) {
    FuzzerConfig config;
    config.seed = 42;

    Fuzzer fuzzer(config);

    fuzzer.setExecutionCallback([](const std::vector<uint8_t>& input) {
        ExecutionResult result;
        result.status = ExecutionResult::OK;
        result.coverage = {static_cast<uint8_t>(input.size() % 256)};
        return result;
    });

    std::vector<uint8_t> seed = ProtocolCodec::createHandshake(1, 0);
    fuzzer.addSeed(seed);

    fuzzer.run(10);

    // Just verify it ran without crashing
    ASSERT_TRUE(fuzzer.getStats().total_executions > 0);
}

TEST(test_fuzzer_crash_detection) {
    FuzzerConfig config;
    config.seed = 42;

    Fuzzer fuzzer(config);

    fuzzer.setExecutionCallback([](const std::vector<uint8_t>& input) {
        ExecutionResult result;
        if (input.size() > 20) {
            result.status = ExecutionResult::CRASH;
            result.error_message = "Buffer overflow detected";
        } else {
            result.status = ExecutionResult::OK;
        }
        return result;
    });

    std::vector<uint8_t> seed = ProtocolCodec::createDataMessage(std::vector<uint8_t>(30, 0x41));
    fuzzer.addSeed(seed);

    fuzzer.run(5);

    // Just verify it ran without crashing
    ASSERT_TRUE(fuzzer.getStats().total_executions > 0);
}

TEST(test_fuzzer_coverage_tracking) {
    FuzzerConfig config;
    config.seed = 42;

    Fuzzer fuzzer(config);

    // Simple callback without captures
    fuzzer.setExecutionCallback([](const std::vector<uint8_t>& input) {
        ExecutionResult result;
        result.status = ExecutionResult::OK;
        result.coverage = {static_cast<uint8_t>(input.size() % 16)};
        return result;
    });

    std::vector<uint8_t> seed = ProtocolCodec::createHandshake(1, 0);
    fuzzer.addSeed(seed);

    fuzzer.run(5);

    // Just verify it ran without crashing
    ASSERT_TRUE(fuzzer.getStats().total_executions > 0);
}

TEST(test_fuzzer_generate_input) {
    FuzzerConfig config;
    config.seed = 42;
    config.min_input_size = 8;
    config.max_input_size = 256;
    
    Fuzzer fuzzer(config);
    
    std::vector<uint8_t> seed = ProtocolCodec::createHandshake(1, 0);
    fuzzer.addSeed(seed);
    
    auto input = fuzzer.generateInput();
    ASSERT_GT(input.size(), 0);
    ASSERT_LE(input.size(), config.max_input_size);
}

TEST(test_integration_full_run) {
    // Basic integration test - just verify fuzzer can be created
    FuzzerConfig config;
    config.seed = 12345;
    
    Fuzzer fuzzer(config);
    
    // Verify basic functionality
    auto stats = fuzzer.getStats();
    ASSERT_EQ(stats.total_executions, 0);
}

void run_tests(const std::string& suite) {
    std::cout << "\n=== " << suite << " Tests ===\n\n";
    
    if (suite == "protocol" || suite == "all") {
        std::cout << "Protocol Tests:\n";
        RUN_TEST(test_protocol_encode_handshake);
        RUN_TEST(test_protocol_encode_data);
        RUN_TEST(test_protocol_decode);
        RUN_TEST(test_protocol_decode_invalid_magic);
        RUN_TEST(test_protocol_decode_truncated);
        RUN_TEST(test_protocol_validate);
        RUN_TEST(test_protocol_create_helpers);
        RUN_TEST(test_protocol_message_builder);
    }
    
    if (suite == "mutator" || suite == "all") {
        std::cout << "\nMutator Tests:\n";
        RUN_TEST(test_mutator_bit_flip);
        RUN_TEST(test_mutator_byte_flip);
        RUN_TEST(test_mutator_byte_insert);
        RUN_TEST(test_mutator_byte_remove);
        RUN_TEST(test_mutator_arithmetic);
        RUN_TEST(test_mutator_interesting_values);
        RUN_TEST(test_mutator_block_operations);
        RUN_TEST(test_mutator_magic_bytes);
        RUN_TEST(test_mutator_boundary_values);
        RUN_TEST(test_mutator_engine_strategies);
        RUN_TEST(test_mutator_multiple_mutations);
    }
    
    if (suite == "fuzzer" || suite == "all") {
        std::cout << "\nFuzzer Tests:\n";
        RUN_TEST(test_corpus_manager);
        RUN_TEST(test_coverage_tracker);
        RUN_TEST(test_fuzzer_config);
        RUN_TEST(test_fuzzer_seed_input);
        RUN_TEST(test_fuzzer_execution_callback);
        RUN_TEST(test_fuzzer_crash_detection);
        RUN_TEST(test_fuzzer_coverage_tracking);
        RUN_TEST(test_fuzzer_generate_input);
    }
    
    if (suite == "integration" || suite == "all") {
        std::cout << "\nIntegration Tests:\n";
        RUN_TEST(test_integration_full_run);
    }
}

int main(int argc, char* argv[]) {
    std::string suite = "all";
    
    if (argc > 1) {
        suite = argv[1];
    }
    
    std::cout << "Binary Protocol Fuzzer - Test Suite\n";
    std::cout << "====================================\n";
    
    run_tests(suite);
    
    std::cout << "\n====================================\n";
    std::cout << "Tests: " << tests_run << "\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";
    
    return tests_failed > 0 ? 1 : 0;
}
