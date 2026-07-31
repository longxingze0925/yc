#ifndef REMOTE_IOS_FFI_H
#define REMOTE_IOS_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RemoteControllerCommandCallback)(
    uint64_t context,
    int32_t command_kind,
    uint64_t connection_epoch,
    int32_t delivery,
    const uint8_t *payload,
    size_t payload_len
);

typedef void (*RemoteControllerEventCallback)(
    uint64_t context,
    int32_t event_kind,
    int32_t state_or_error,
    const uint8_t *payload,
    size_t payload_len,
    int64_t presentation_time_millis,
    bool is_keyframe,
    uint64_t frame_id
);

typedef struct RemoteControllerCallbacks {
    uint64_t context;
    RemoteControllerCommandCallback on_command;
    RemoteControllerEventCallback on_event;
} RemoteControllerCallbacks;

typedef void (*RemoteQuicStateCallback)(
    uint64_t context,
    uint64_t transport_handle,
    int32_t state,
    const uint8_t *detail,
    size_t detail_len
);

typedef void (*RemoteQuicPacketCallback)(
    uint64_t context,
    uint64_t transport_handle,
    int32_t delivery,
    uint16_t channel_id,
    uint64_t packet_group_id,
    uint32_t packet_index,
    uint32_t packet_count,
    const uint8_t *packet,
    size_t packet_len
);
/* VIDEO groups contain exactly two packets: index 0 is 0x0110, index 1 is 0x0111. */

typedef void (*RemoteQuicDisconnectCallback)(
    uint64_t context,
    uint64_t transport_handle,
    int32_t result,
    const uint8_t *reason,
    size_t reason_len
);

typedef void (*RemoteQuicClosedCallback)(uint64_t context, uint64_t transport_handle);

typedef struct RemoteQuicCallbacks {
    uint64_t context;
    RemoteQuicStateCallback on_state;
    RemoteQuicPacketCallback on_packet;
    RemoteQuicDisconnectCallback on_disconnect;
    RemoteQuicClosedCallback on_closed;
} RemoteQuicCallbacks;

enum RemoteControllerResult {
    REMOTE_CONTROLLER_OK = 0,
    REMOTE_CONTROLLER_INVALID_ARGUMENT = 1,
    REMOTE_CONTROLLER_INVALID_HANDLE = 2,
    REMOTE_CONTROLLER_INVALID_STATE = 3,
    REMOTE_CONTROLLER_INVALID_INPUT = 4,
    REMOTE_CONTROLLER_TRANSPORT_ERROR = 5,
    REMOTE_CONTROLLER_SECURITY_ERROR = 6,
    REMOTE_CONTROLLER_PANIC = 255
};

enum RemoteControllerCommandKind {
    REMOTE_CONTROLLER_COMMAND_START = 1,
    REMOTE_CONTROLLER_COMMAND_CLOSE = 3,
    REMOTE_CONTROLLER_COMMAND_SIGN_KEY_EXCHANGE = 4,
    REMOTE_CONTROLLER_COMMAND_SEND_KEY_EXCHANGE = 5,
    REMOTE_CONTROLLER_COMMAND_SEND_KEY_CONFIRM = 6,
    /* payload = 40-byte RCTL header followed by application-layer ciphertext. */
    REMOTE_CONTROLLER_COMMAND_SEND_SECURE_PACKET = 7
};

enum RemoteControllerEventKind {
    REMOTE_CONTROLLER_EVENT_STATE = 1,
    REMOTE_CONTROLLER_EVENT_H264 = 2,
    REMOTE_CONTROLLER_EVENT_RECOVERABLE_ERROR = 3,
    REMOTE_CONTROLLER_EVENT_FATAL_ERROR = 4,
    REMOTE_CONTROLLER_EVENT_VIDEO_FORMAT = 5
};

enum RemoteControllerState {
    REMOTE_CONTROLLER_STATE_IDLE = 0,
    REMOTE_CONTROLLER_STATE_CONNECTING = 1,
    REMOTE_CONTROLLER_STATE_STREAMING = 2,
    REMOTE_CONTROLLER_STATE_RECONNECTING = 3,
    REMOTE_CONTROLLER_STATE_CLOSED = 4
};

enum RemoteControllerTransportEventKind {
    REMOTE_CONTROLLER_TRANSPORT_DISCONNECTED_RECOVERABLE = 2,
    REMOTE_CONTROLLER_TRANSPORT_DISCONNECTED_FATAL = 3,
    REMOTE_CONTROLLER_TRANSPORT_CLOSED = 4
};

enum RemoteQuicState {
    REMOTE_QUIC_STATE_BOUND = 1,
    REMOTE_QUIC_STATE_CONNECTING = 2,
    REMOTE_QUIC_STATE_CONNECTED = 3
};

enum RemoteQuicDelivery {
    REMOTE_QUIC_DELIVERY_REALTIME = 1,
    REMOTE_QUIC_DELIVERY_RELIABLE = 2,
    REMOTE_QUIC_DELIVERY_VIDEO = 3
};

uint64_t remote_controller_session_create(
    uint64_t session_id_high,
    uint64_t session_id_low,
    RemoteControllerCallbacks callbacks
);
int32_t remote_controller_session_connect(uint64_t handle);
int32_t remote_controller_session_configure_handshake_json(
    uint64_t handle,
    const uint8_t *payload,
    size_t payload_len
);
int32_t remote_controller_session_submit_key_exchange_signature(
    uint64_t handle,
    const uint8_t *signature,
    size_t signature_len
);
int32_t remote_controller_session_receive_peer_key_exchange_json(
    uint64_t handle,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t *peer_device_public_key,
    size_t peer_device_public_key_len,
    uint64_t now_epoch_millis,
    uint64_t key_confirm_timestamp_epoch_millis
);
int32_t remote_controller_session_receive_peer_key_confirm_json(
    uint64_t handle,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t now_epoch_millis
);
int32_t remote_controller_session_send_input_json(
    uint64_t handle,
    const uint8_t *payload,
    size_t payload_len
);
int32_t remote_controller_session_send_keyframe_request_json(
    uint64_t handle,
    const uint8_t *payload,
    size_t payload_len
);
int32_t remote_controller_session_transport_event(
    uint64_t handle,
    uint64_t connection_epoch,
    int32_t event_kind,
    const uint8_t *reason,
    size_t reason_len
);
int32_t remote_controller_session_receive_secure_video_frame(
    uint64_t handle,
    const uint8_t *info_packet,
    size_t info_packet_len,
    const uint8_t *data_packet,
    size_t data_packet_len
);
int32_t remote_controller_session_close(uint64_t handle);
int32_t remote_controller_session_destroy(uint64_t handle);

/* Must be called only after the controller session has verified peer key_confirm. */
uint64_t remote_controller_quic_transport_create(
    uint64_t session_handle,
    RemoteQuicCallbacks callbacks
);
/* The certificate is the single-session DER certificate authenticated by signaling. */
int32_t remote_controller_quic_transport_bind(
    uint64_t handle,
    const uint8_t *local_addr,
    size_t local_addr_len,
    const uint8_t *peer_certificate_der,
    size_t peer_certificate_der_len
);
/*
 * Duplicates a caller-owned, already-bound UDP socket. Use this after the
 * candidate authorization probe so QUIC keeps the exact authorized endpoint.
 */
int32_t remote_controller_quic_transport_bind_socket(
    uint64_t handle,
    int32_t socket_fd,
    const uint8_t *peer_certificate_der,
    size_t peer_certificate_der_len
);
int32_t remote_controller_quic_transport_connect(
    uint64_t handle,
    const uint8_t *remote_addr,
    size_t remote_addr_len,
    const uint8_t *server_name,
    size_t server_name_len
);
int32_t remote_controller_quic_transport_send_reliable(
    uint64_t handle,
    const uint8_t *packet,
    size_t packet_len
);
int32_t remote_controller_quic_transport_send_realtime(
    uint64_t handle,
    const uint8_t *packet,
    size_t packet_len
);
int32_t remote_controller_quic_transport_close(uint64_t handle);
int32_t remote_controller_quic_transport_destroy(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
