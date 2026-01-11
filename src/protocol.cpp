#include "protocol.h"
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace fuzzproto {

std::vector<uint8_t> ProtocolCodec::encode(MessageType type, const std::vector<uint8_t>& payload,
                                            uint8_t flags, uint16_t sequence) {
    std::vector<uint8_t> message;
    
    if (payload.size() > MAX_PAYLOAD_SIZE) {
        throw std::invalid_argument("Payload exceeds maximum size");
    }

    ProtocolHeader header;
    header.magic[0] = MAGIC_BYTE1;
    header.magic[1] = MAGIC_BYTE2;
    header.type = type;
    header.flags = flags;
    header.sequence = sequence;
    header.payload_len = static_cast<uint16_t>(payload.size());

    message.resize(HEADER_SIZE + payload.size());
    std::memcpy(message.data(), &header, HEADER_SIZE);
    
    if (!payload.empty()) {
        std::memcpy(message.data() + HEADER_SIZE, payload.data(), payload.size());
    }

    return message;
}

ParsedMessage ProtocolCodec::decode(const std::vector<uint8_t>& data) {
    ParsedMessage result;
    result.valid = false;

    if (data.size() < HEADER_SIZE) {
        result.error_message = "Data too short for header";
        return result;
    }

    std::memcpy(&result.header, data.data(), HEADER_SIZE);

    if (!validateMagic(data)) {
        result.error_message = "Invalid magic bytes";
        return result;
    }

    size_t expected_size = HEADER_SIZE + result.header.payload_len;
    if (data.size() < expected_size) {
        result.error_message = "Payload length mismatch";
        return result;
    }

    if (result.header.payload_len > 0) {
        result.payload.resize(result.header.payload_len);
        std::memcpy(result.payload.data(), data.data() + HEADER_SIZE, result.header.payload_len);
    }

    result.valid = true;
    return result;
}

ValidationResult ProtocolCodec::validate(const std::vector<uint8_t>& data) {
    if (data.size() < HEADER_SIZE) {
        return ValidationResult::MALFORMED;
    }

    if (!validateMagic(data)) {
        return ValidationResult::INVALID_MAGIC;
    }

    if (!validateLength(data)) {
        return ValidationResult::INVALID_LENGTH;
    }

    return ValidationResult::VALID;
}

uint8_t ProtocolCodec::calculateChecksum(const std::vector<uint8_t>& data) {
    uint8_t checksum = 0;
    for (uint8_t byte : data) {
        checksum ^= byte;
    }
    return checksum;
}

std::string ProtocolCodec::messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::HANDSHAKE: return "HANDSHAKE";
        case MessageType::DATA: return "DATA";
        case MessageType::ACK: return "ACK";
        case MessageType::NACK: return "NACK";
        case MessageType::HEARTBEAT: return "HEARTBEAT";
        case MessageType::DISCONNECT: return "DISCONNECT";
        case MessageType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

std::vector<uint8_t> ProtocolCodec::createHandshake(uint16_t version, uint16_t capabilities) {
    std::vector<uint8_t> payload(4);
    payload[0] = static_cast<uint8_t>(version >> 8);
    payload[1] = static_cast<uint8_t>(version & 0xFF);
    payload[2] = static_cast<uint8_t>(capabilities >> 8);
    payload[3] = static_cast<uint8_t>(capabilities & 0xFF);
    
    ProtocolCodec codec;
    return codec.encode(MessageType::HANDSHAKE, payload);
}

std::vector<uint8_t> ProtocolCodec::createDataMessage(const std::vector<uint8_t>& data,
                                                       uint16_t sequence) {
    ProtocolCodec codec;
    return codec.encode(MessageType::DATA, data, 0, sequence);
}

std::vector<uint8_t> ProtocolCodec::createHeartbeat(uint32_t timestamp) {
    std::vector<uint8_t> payload(4);
    payload[0] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    payload[1] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    payload[2] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    payload[3] = static_cast<uint8_t>(timestamp & 0xFF);
    
    ProtocolCodec codec;
    return codec.encode(MessageType::HEARTBEAT, payload);
}

bool ProtocolCodec::validateMagic(const std::vector<uint8_t>& data) const {
    if (data.size() < 2) return false;
    return data[0] == MAGIC_BYTE1 && data[1] == MAGIC_BYTE2;
}

bool ProtocolCodec::validateLength(const std::vector<uint8_t>& data) const {
    if (data.size() < HEADER_SIZE) return false;
    
    ProtocolHeader header;
    std::memcpy(&header, data.data(), HEADER_SIZE);
    
    size_t expected_size = HEADER_SIZE + header.payload_len;
    return data.size() >= expected_size;
}

bool ProtocolCodec::validateChecksum(const std::vector<uint8_t>& data) const {
    if (data.size() < HEADER_SIZE + 1) return true;
    
    ProtocolHeader header;
    std::memcpy(&header, data.data(), HEADER_SIZE);
    
    if (header.payload_len == 0) return true;
    
    size_t payload_end = HEADER_SIZE + header.payload_len;
    if (data.size() < payload_end + 1) return true;
    
    std::vector<uint8_t> payload(data.begin() + HEADER_SIZE, data.begin() + payload_end);
    uint8_t expected = data[payload_end];
    return calculateChecksum(payload) == expected;
}

MessageBuilder::MessageBuilder() {
    reset();
}

MessageBuilder& MessageBuilder::setType(MessageType type) {
    m_type = type;
    return *this;
}

MessageBuilder& MessageBuilder::setFlags(uint8_t flags) {
    m_flags = flags;
    return *this;
}

MessageBuilder& MessageBuilder::setSequence(uint16_t seq) {
    m_sequence = seq;
    return *this;
}

MessageBuilder& MessageBuilder::setPayload(const std::vector<uint8_t>& payload) {
    m_payload = payload;
    return *this;
}

MessageBuilder& MessageBuilder::setPayload(const std::string& payload) {
    m_payload.assign(payload.begin(), payload.end());
    return *this;
}

MessageBuilder& MessageBuilder::addByte(uint8_t byte) {
    m_payload.push_back(byte);
    return *this;
}

MessageBuilder& MessageBuilder::addUint16(uint16_t value) {
    m_payload.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    m_payload.push_back(static_cast<uint8_t>(value & 0xFF));
    return *this;
}

MessageBuilder& MessageBuilder::addUint32(uint32_t value) {
    m_payload.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    m_payload.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    m_payload.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    m_payload.push_back(static_cast<uint8_t>(value & 0xFF));
    return *this;
}

MessageBuilder& MessageBuilder::addString(const std::string& str) {
    m_payload.insert(m_payload.end(), str.begin(), str.end());
    return *this;
}

std::vector<uint8_t> MessageBuilder::build() const {
    ProtocolCodec codec;
    return codec.encode(m_type, m_payload, m_flags, m_sequence);
}

void MessageBuilder::reset() {
    m_type = MessageType::DATA;
    m_flags = 0;
    m_sequence = 0;
    m_payload.clear();
}

} // namespace fuzzproto
