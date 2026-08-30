// PlistPayload.cpp
//
// libplist-backed implementation of the narrow bplist shapes this project
// needs (see PlistPayload.h for the VERIFIED FROM SOURCE shape catalogue).
// Deliberately does not hand-roll any bplist parsing/serialization itself —
// every byte in/out goes through plist_from_bin/plist_to_bin.

#include "PlistPayload.h"
#include <plist/plist.h>
#include <cstdlib>

namespace t2::bridgexpc {

namespace {

struct PlistGuard {
    plist_t p;
    ~PlistGuard() { if (p) plist_free(p); }
};

std::vector<uint8_t> PlistToBinary(plist_t node) {
    char* data = nullptr;
    uint32_t length = 0;
    plist_to_bin(node, &data, &length);
    std::vector<uint8_t> out;
    if (data && length) {
        out.assign(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + length);
    }
    if (data) {
        free(data);
    }
    return out;
}

plist_t ParseRootArray(const std::vector<uint8_t>& bytes, uint32_t expectedSize) {
    if (bytes.empty()) return nullptr;
    plist_t root = nullptr;
    plist_from_bin(reinterpret_cast<const char*>(bytes.data()),
                    static_cast<uint32_t>(bytes.size()), &root);
    if (!root) return nullptr;
    if (plist_get_node_type(root) != PLIST_ARRAY ||
        plist_array_get_size(root) != expectedSize) {
        plist_free(root);
        return nullptr;
    }
    return root;
}

} // namespace

std::optional<MessageEnvelope> ParseMessageBody(const std::vector<uint8_t>& bplistBody) {
    plist_t root = ParseRootArray(bplistBody, 4);
    if (!root) return std::nullopt;
    PlistGuard guard{root};

    plist_t versionNode = plist_array_get_item(root, 0);
    plist_t isReplyNode = plist_array_get_item(root, 1);
    plist_t requestIdNode = plist_array_get_item(root, 2);
    plist_t payloadNode = plist_array_get_item(root, 3);

    if (!versionNode || !isReplyNode || !requestIdNode || !payloadNode) {
        return std::nullopt;
    }
    if (plist_get_node_type(versionNode) != PLIST_UINT ||
        plist_get_node_type(isReplyNode) != PLIST_BOOLEAN ||
        plist_get_node_type(requestIdNode) != PLIST_STRING) {
        return std::nullopt;
    }

    MessageEnvelope env;

    uint64_t versionVal = 0;
    plist_get_uint_val(versionNode, &versionVal);
    env.version = static_cast<int64_t>(versionVal);

    uint8_t isReplyVal = 0;
    plist_get_bool_val(isReplyNode, &isReplyVal);
    env.isReply = (isReplyVal != 0);

    char* reqIdStr = nullptr;
    plist_get_string_val(requestIdNode, &reqIdStr);
    if (!reqIdStr) return std::nullopt;
    env.requestId = reqIdStr;
    free(reqIdStr);

    // Re-encode the payload node as its own standalone bplist blob so
    // callers (BiometricKit) can decode it independently without this
    // wrapper needing to know every possible payload shape up front.
    env.payloadPlist = PlistToBinary(payloadNode);
    return env;
}

namespace {

plist_t BuildPayloadArray(const std::vector<int64_t>& leadingInts,
                           const std::vector<uint8_t>* trailingBlob,
                           const std::vector<int64_t>& trailingInts) {
    plist_t payload = plist_new_array();
    for (int64_t v : leadingInts) {
        plist_array_append_item(payload, plist_new_uint(static_cast<uint64_t>(v)));
    }
    if (trailingBlob) {
        plist_array_append_item(
            payload,
            plist_new_data(reinterpret_cast<const char*>(trailingBlob->data()),
                            static_cast<uint32_t>(trailingBlob->size())));
    }
    for (int64_t v : trailingInts) {
        plist_array_append_item(payload, plist_new_uint(static_cast<uint64_t>(v)));
    }
    return payload;
}

std::vector<uint8_t> EncodeEnvelope(int64_t version, bool isReply,
                                     const std::string& requestId, plist_t payload) {
    plist_t root = plist_new_array();
    plist_array_append_item(root, plist_new_uint(static_cast<uint64_t>(version)));
    plist_array_append_item(root, plist_new_bool(isReply ? 1 : 0));
    plist_array_append_item(root, plist_new_string(requestId.c_str()));
    plist_array_append_item(root, payload); // ownership transferred to root array

    auto bytes = PlistToBinary(root);
    plist_free(root); // frees payload too, since it is now root's child
    return bytes;
}

} // namespace

std::vector<uint8_t> EncodeAckEnvelope(const std::string& requestId) {
    // VERIFIED FROM SOURCE: ack shape is [1, true, requestId, [0]].
    plist_t payload = plist_new_array();
    plist_array_append_item(payload, plist_new_uint(0));
    return EncodeEnvelope(kEnvelopeVersion, /*isReply=*/true, requestId, payload);
}

std::vector<uint8_t> EncodeRequestEnvelope(const std::string& requestId,
                                            const std::vector<int64_t>& leadingInts,
                                            const std::vector<uint8_t>* trailingBlob,
                                            const std::vector<int64_t>& trailingInts) {
    plist_t payload = BuildPayloadArray(leadingInts, trailingBlob, trailingInts);
    return EncodeEnvelope(kEnvelopeVersion, /*isReply=*/false, requestId, payload);
}

std::optional<std::vector<int64_t>> DecodeIntArrayPayload(const std::vector<uint8_t>& payloadPlist) {
    if (payloadPlist.empty()) return std::nullopt;
    plist_t root = nullptr;
    plist_from_bin(reinterpret_cast<const char*>(payloadPlist.data()),
                    static_cast<uint32_t>(payloadPlist.size()), &root);
    if (!root) return std::nullopt;
    PlistGuard guard{root};

    if (plist_get_node_type(root) != PLIST_ARRAY) return std::nullopt;

    uint32_t count = plist_array_get_size(root);
    std::vector<int64_t> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        plist_t item = plist_array_get_item(root, i);
        if (!item || plist_get_node_type(item) != PLIST_UINT) return std::nullopt;
        uint64_t v = 0;
        plist_get_uint_val(item, &v);
        out.push_back(static_cast<int64_t>(v));
    }
    return out;
}

std::optional<std::vector<uint8_t>> DecodeSingleBlobPayload(const std::vector<uint8_t>& payloadPlist) {
    plist_t root = ParseRootArray(payloadPlist, 1);
    if (!root) return std::nullopt;
    PlistGuard guard{root};

    plist_t blobNode = plist_array_get_item(root, 0);
    if (!blobNode || plist_get_node_type(blobNode) != PLIST_DATA) return std::nullopt;

    char* data = nullptr;
    uint64_t length = 0;
    plist_get_data_val(blobNode, &data, &length);
    std::vector<uint8_t> out;
    if (data && length) {
        out.assign(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + length);
    }
    if (data) free(data);
    return out;
}

std::optional<std::vector<uint8_t>> DecodeStatusEventData(const std::vector<uint8_t>& payloadPlist) {
    // VERIFIED FROM SOURCE (bridge-xpc-probe.py summarize_event):
    // isinstance(payload, list) and len(payload) == 5 and payload[0] == 9.
    plist_t root = ParseRootArray(payloadPlist, 5);
    if (!root) return std::nullopt;
    PlistGuard guard{root};

    plist_t methodNode = plist_array_get_item(root, 0);
    plist_t dataNode = plist_array_get_item(root, 2);
    if (!methodNode || plist_get_node_type(methodNode) != PLIST_UINT) return std::nullopt;

    uint64_t method = 0;
    plist_get_uint_val(methodNode, &method);
    if (method != 9) return std::nullopt;

    if (!dataNode || plist_get_node_type(dataNode) != PLIST_DATA) return std::nullopt;

    char* data = nullptr;
    uint64_t length = 0;
    plist_get_data_val(dataNode, &data, &length);
    std::vector<uint8_t> out;
    if (data && length) {
        out.assign(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + length);
    }
    if (data) free(data);
    return out;
}

} // namespace t2::bridgexpc
