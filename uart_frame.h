#ifndef UART_FRAME_H
#define UART_FRAME_H

/*
 * Authenticated + encrypted master/slave framing using AES-128-CCM.
 *
 * All frames:  SOF | ADDR | TYPE | LEN | EXT | CIPHERTEXT (LEN) | TAG
 *   AAD   = ADDR | TYPE | LEN | EXT          (authenticated, not encrypted)
 *   Nonce = TYPE | ADDR | <type specific>    (13 bytes, zero padded)
 *
 *   TYPE       ADDR       EXT              nonce tail
 *   REQUEST    slave      SEQ (4, LE)      SEQ
 *   RESPONSE   slave      -                SEQ of the request answered
 *   DFU_CHUNK  0xFF       INDEX (2, LE)    UPDATE_ID (4, LE) | INDEX
 *
 * NONCE RULES (CCM is broken if a nonce repeats under the same key with
 * different data):
 *   - The master must never reuse a SEQ for the same slave address.
 *     Keep the counter in persistent (battery-backed) storage.
 *   - A slave must send at most one response per accepted request SEQ.
 *     Reject requests whose SEQ is not greater than the last accepted one;
 *     never answer a replayed or retransmitted request.
 *   - DFU chunks use a fresh random image key per update. Re-broadcasting
 *     the same chunk (same index, same data) is safe.
 */

#include <stdint.h>
#include <stddef.h>

#define UART_SOF          0x7E
#define UART_SEQ_SIZE     4
#define UART_INDEX_SIZE   2
#define UART_TAG_SIZE     8     /* CCM allows 4, 6, 8, 10, 12, 14, 16 */
#define UART_KEY_SIZE     16
#define UART_MAX_PAYLOAD  255

#define UART_ADDR_BROADCAST 0xFF  /* reserved: not a valid slave address */

#define UART_TYPE_REQUEST   0x01
#define UART_TYPE_RESPONSE  0x02
#define UART_TYPE_DFU_CHUNK 0x03

#define UART_HEADER_SIZE        4   /* SOF, ADDR, TYPE, LEN */
#define UART_REQUEST_OVERHEAD   (UART_HEADER_SIZE + UART_SEQ_SIZE + UART_TAG_SIZE)
#define UART_RESPONSE_OVERHEAD  (UART_HEADER_SIZE + UART_TAG_SIZE)
#define UART_CHUNK_OVERHEAD     (UART_HEADER_SIZE + UART_INDEX_SIZE + UART_TAG_SIZE)

#define UART_REQUEST_MAX_SIZE   (UART_REQUEST_OVERHEAD + UART_MAX_PAYLOAD)
#define UART_RESPONSE_MAX_SIZE  (UART_RESPONSE_OVERHEAD + UART_MAX_PAYLOAD)
#define UART_CHUNK_MAX_SIZE     (UART_CHUNK_OVERHEAD + UART_MAX_PAYLOAD)

#define UART_MAX_FRAME_SIZE     UART_CHUNK_MAX_SIZE

typedef enum {
    UART_OK = 0,
    UART_ERR_ARGUMENT,
    UART_ERR_LENGTH,
    UART_ERR_BUFFER,
    UART_ERR_FORMAT,
    UART_ERR_ADDR,      /* frame is for another slave: ignore silently */
    UART_ERR_AUTH,      /* tag check failed */
    UART_ERR_CRYPTO,
    UART_ERR_STATE      /* operation not valid in the current state */
} uart_status_t;

/*
 * Returns the TYPE of a frame (after basic header checks) so a receiver
 * can dispatch it, or 0 if the frame is malformed.
 */
uint8_t uart_frame_type(const uint8_t *src, size_t src_len);

/* Master -> Slave */

uart_status_t uart_encode_request(
    const uint8_t *key,
    uint8_t addr,
    const uint8_t *payload,
    size_t payload_len,
    uint32_t seq,
    uint8_t *dst,
    size_t *dst_len);

/*
 * Slave side. Returns UART_ERR_ADDR (before any crypto) for frames addressed
 * to other slaves. On success, *seq holds the request SEQ: the caller MUST
 * check it is greater than the last accepted SEQ before acting on it.
 */
uart_status_t uart_decode_request(
    const uint8_t *key,
    uint8_t addr,
    const uint8_t *src,
    size_t src_len,
    uint8_t *payload,
    size_t *payload_len,
    uint32_t *seq);

/* Slave -> Master. seq is the SEQ of the request being answered. */

uart_status_t uart_encode_response(
    const uint8_t *key,
    uint8_t addr,
    const uint8_t *payload,
    size_t payload_len,
    uint32_t seq,
    uint8_t *dst,
    size_t *dst_len);

/* Master side. seq is the SEQ of the outstanding request. */
uart_status_t uart_decode_response(
    const uint8_t *key,
    uint8_t addr,
    const uint8_t *src,
    size_t src_len,
    uint32_t seq,
    uint8_t *payload,
    size_t *payload_len);

/* Master -> all slaves (broadcast). image_key is the per-update key. */

uart_status_t uart_encode_dfu_chunk(
    const uint8_t *image_key,
    uint32_t update_id,
    uint16_t index,
    const uint8_t *data,
    size_t data_len,
    uint8_t *dst,
    size_t *dst_len);

uart_status_t uart_decode_dfu_chunk(
    const uint8_t *image_key,
    uint32_t update_id,
    const uint8_t *src,
    size_t src_len,
    uint16_t *index,
    uint8_t *data,
    size_t *data_len);

#endif
