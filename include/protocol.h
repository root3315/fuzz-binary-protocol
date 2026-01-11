#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <optional>

namespace fuzzproto {

// Protocol message types
enum class MessageType : uint8_t {
    HANDSHAKE = 0x01,
    DATA = 0x02,
    ACK = 0x03,
    NACK = 0x04,
    HEARTBEAT = 0x05,
    DISCONNECT = 0x06,
    CUSTOM = 0xFF
};

// Protocol header structure (8 bytes)
#pragma pack(push, 1)
struct ProtocolHeader {
    uint8_t magic[2];       // Magic bytes: 0xBE, 0xEF
    MessageType type;       // Message type
    uint8_t flags;          // Flags field
    uint16_t sequence;      // Sequence number
    uint16_t payload_len;   // Payload length
};
#pragma pack(pop)

// Parsed message structure
struct ParsedMessage {
    ProtocolHeader header;
    std::vector<uint8_t> payload;
    bool valid;
    std::string error_message;
};

// Protocol validation result
enum class ValidationResult {
    VALID,
    INVALID_MAGIC,
    INVALID_LENGTH,
    INVALID_TYPE,
    CHECKSUM_MISMATCH,
    MALFORMED
};

// Protocol encoder/decoder class
class ProtocolCodec {
public:
    static constexpr uint8_t MAGIC_BYTE1 = 0xBE;
    static constexpr uint8_t MAGIC_BYTE2 = 0xEF;
    static constexpr size_t HEADER_SIZE = sizeof(ProtocolHeader);
    static constexpr size_t MAX_PAYLOAD_SIZE = 65535;
    static constexpr size_t MIN_MESSAGE_SIZE = HEADER_SIZE;

    ProtocolCodec() = default;
    ~ProtocolCodec() = default;

    // Encode a message into binary format
    std::vector<uint8_t> encode(MessageType type, const std::vector<uint8_t>& payload,
                                 uint8_t flags = 0, uint16_t sequence = 0);

    // Decode binary data into a parsed message
    ParsedMessage decode(const std::vector<uint8_t>& data);

    // Validate a raw message buffer
    ValidationResult validate(const std::vector<uint8_t>& data);

    // Calculate checksum for payload
    static uint8_t calculateChecksum(const std::vector<uint8_t>& data);

    // Get message type as string
    static std::string messageTypeToString(MessageType type);

    // Generate a valid handshake message
    static std::vector<uint8_t> createHandshake(uint16_t version = 1, uint16_t capabilities = 0);

    // Generate a valid data message
    static std::vector<uint8_t> createDataMessage(const std::vector<uint8_t>& data,
                                                   uint16_t sequence = 0);

    // Generate a valid heartbeat message
    static std::vector<uint8_t> createHeartbeat(uint32_t timestamp = 0);

private:
    bool validateMagic(const std::vector<uint8_t>& data) const;
    bool validateLength(const std::vector<uint8_t>& data) const;
    bool validateChecksum(const std::vector<uint8_t>& data) const;
};

// Message builder for fluent API
class MessageBuilder {
public:
    MessageBuilder();
    ~MessageBuilder() = default;

    MessageBuilder& setType(MessageType type);
    MessageBuilder& setFlags(uint8_t flags);
    MessageBuilder& setSequence(uint16_t seq);
    MessageBuilder& setPayload(const std::vector<uint8_t>& payload);
    MessageBuilder& setPayload(const std::string& payload);
    MessageBuilder& addByte(uint8_t byte);
    MessageBuilder& addUint16(uint16_t value);
    MessageBuilder& addUint32(uint32_t value);
    MessageBuilder& addString(const std::string& str);

    std::vector<uint8_t> build() const;
    void reset();

private:
    MessageType m_type = MessageType::DATA;
    uint8_t m_flags = 0;
    uint16_t m_sequence = 0;
    std::vector<uint8_t> m_payload;
};

} // namespace fuzzproto

#endif // PROTOCOL_H
