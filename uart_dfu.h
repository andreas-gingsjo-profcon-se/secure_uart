#ifndef UART_DFU_H
#define UART_DFU_H

/*
 * Broadcast DFU over the secure UART framing.
 *
 * Flow (master):
 *   1. BEGIN    unicast to each slave (CCM, per-slave key + SEQ):
 *               update_id, image_size, chunk_size, SHA-256(DFU file),
 *               image_key (fresh random 16 bytes per update).
 *   2. CHUNKS   broadcast to all slaves, encrypted with image_key.
 *   3. STATUS   unicast to each slave; reply carries a bitmap of missing
 *               chunks. Re-broadcast the union, repeat until complete.
 *   4. FINISH   unicast: slave hashes the staged file, compares with the
 *               BEGIN hash, then calls verify_signature() on it.
 *   5. ACTIVATE unicast: only accepted after a successful FINISH.
 *
 * Security properties:
 *   - Outsiders cannot inject chunks (no image_key).
 *   - A compromised slave knows image_key and can inject chunks, but the
 *     SHA-256 check (BEGIN hash came over that slave's own unicast channel)
 *     rejects the result. Worst case: denial of service.
 *   - A compromised master can send any hash, but verify_signature() checks
 *     the vendor signature inside the DFU file. Anti-rollback (version
 *     check) belongs in verify_signature() too, since the version is signed.
 *   - Re-broadcasting a chunk is safe (same key, nonce and data).
 */

#include <stdint.h>
#include <stddef.h>

#include "uart_frame.h"

#define UART_DFU_HASH_SIZE     32
#define UART_DFU_CHUNK_SIZE    240   /* recommended; must be 1..255 */

/* Request payload byte 0 */
#define UART_DFU_CMD_BEGIN     0x10
#define UART_DFU_CMD_STATUS    0x11
#define UART_DFU_CMD_FINISH    0x12
#define UART_DFU_CMD_ACTIVATE  0x13
#define UART_DFU_CMD_ABORT     0x14

#define UART_DFU_BEGIN_SIZE    (1 + 4 + 4 + 1 + UART_DFU_HASH_SIZE + UART_KEY_SIZE)

/* STATUS response: result | state | update_id (4) | missing (2) | bitmap */
#define UART_DFU_STATUS_HDR    8
#define UART_DFU_BITMAP_MAX    (UART_MAX_PAYLOAD - UART_DFU_STATUS_HDR)
#define UART_DFU_MAX_CHUNKS    (UART_DFU_BITMAP_MAX * 8)   /* 1976 */

typedef enum {
    UART_DFU_IDLE = 0,
    UART_DFU_RECEIVING,
    UART_DFU_VERIFIED,
    UART_DFU_FAILED
} uart_dfu_state_t;

/* Response payload byte 0 */
typedef enum {
    UART_DFU_RES_OK = 0,
    UART_DFU_RES_BAD_REQUEST,
    UART_DFU_RES_BAD_STATE,
    UART_DFU_RES_TOO_LARGE,
    UART_DFU_RES_FLASH_ERROR,
    UART_DFU_RES_INCOMPLETE,
    UART_DFU_RES_HASH_MISMATCH,
    UART_DFU_RES_SIGNATURE_INVALID,
    UART_DFU_RES_ACTIVATE_FAILED
} uart_dfu_result_t;

/* Slave-side platform hooks. All return 0 on success. */
typedef struct {
    void  *user;
    size_t slot_size;   /* staging slot capacity in bytes */

    int (*erase)(void *user, size_t size);
    int (*write)(void *user, size_t offset, const uint8_t *data, size_t len);
    int (*read)(void *user, size_t offset, uint8_t *data, size_t len);

    /* Check the vendor signature (and anti-rollback version) of the DFU
     * file now in the staging slot. Called only after the hash matched. */
    int (*verify_signature)(void *user, size_t image_size);

    /* Mark the staged image for boot. Should schedule the reboot rather
     * than reboot immediately, so the response can still be sent. */
    int (*activate)(void *user, size_t image_size);
} uart_dfu_ops_t;

typedef struct {
    const uart_dfu_ops_t *ops;
    uart_dfu_state_t state;
    uint32_t update_id;
    uint32_t image_size;
    uint8_t  chunk_size;
    uint16_t n_chunks;
    uint16_t received;
    uint8_t  hash[UART_DFU_HASH_SIZE];
    uint8_t  image_key[UART_KEY_SIZE];
    uint8_t  bitmap[UART_DFU_BITMAP_MAX];   /* bit set = chunk received */
} uart_dfu_slave_t;

/* ---- Slave ----------------------------------------------------------- */

void uart_dfu_slave_init(uart_dfu_slave_t *s, const uart_dfu_ops_t *ops);

/* Reset to IDLE and wipe the image key. */
void uart_dfu_slave_reset(uart_dfu_slave_t *s);

/* True if a decoded request payload is a DFU command. */
int uart_dfu_is_command(const uint8_t *payload, size_t len);

/*
 * Handle a DFU command from an already decoded, replay-checked request.
 * Writes the plaintext response payload to resp; the caller encrypts it
 * with uart_encode_response().
 */
uart_status_t uart_dfu_slave_handle_command(
    uart_dfu_slave_t *s,
    const uint8_t *req, size_t req_len,
    uint8_t *resp, size_t *resp_len);

/*
 * Handle a received broadcast DFU_CHUNK frame. Returns UART_ERR_STATE if no
 * update is in progress (ignore), UART_ERR_AUTH for forged chunks.
 */
uart_status_t uart_dfu_slave_handle_chunk(
    uart_dfu_slave_t *s,
    const uint8_t *frame, size_t frame_len);

/* ---- Master ---------------------------------------------------------- */

uint16_t uart_dfu_chunk_count(uint32_t image_size, uint8_t chunk_size);

uart_status_t uart_dfu_build_begin(
    uint32_t update_id,
    uint32_t image_size,
    uint8_t chunk_size,
    const uint8_t hash[UART_DFU_HASH_SIZE],
    const uint8_t image_key[UART_KEY_SIZE],
    uint8_t *out, size_t *out_len);

typedef struct {
    uart_dfu_result_t result;
    uart_dfu_state_t  state;
    uint32_t update_id;
    uint16_t missing;
    const uint8_t *bitmap;   /* bit set = chunk missing; points into resp */
    size_t bitmap_len;
} uart_dfu_status_t;

uart_status_t uart_dfu_parse_status(
    const uint8_t *resp, size_t resp_len, uart_dfu_status_t *out);

static inline int uart_dfu_bit(const uint8_t *bitmap, size_t i)
{
    return (bitmap[i / 8] >> (i % 8)) & 1;
}

#endif
