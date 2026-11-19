#include "uart_dfu.h"

#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

static void put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t get_le32(const uint8_t *p)
{
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

uint16_t uart_dfu_chunk_count(uint32_t image_size, uint8_t chunk_size)
{
    if (chunk_size == 0)
        return 0;
    uint32_t n = (image_size + chunk_size - 1) / chunk_size;
    return n > UART_DFU_MAX_CHUNKS ? 0 : (uint16_t)n;
}

static size_t chunk_len(const uart_dfu_slave_t *s, uint16_t index)
{
    if (index + 1u < s->n_chunks)
        return s->chunk_size;
    return s->image_size - (size_t)index * s->chunk_size;
}

/* ---- Slave ----------------------------------------------------------- */

void uart_dfu_slave_init(uart_dfu_slave_t *s, const uart_dfu_ops_t *ops)
{
    memset(s, 0, sizeof(*s));
    s->ops = ops;
    s->state = UART_DFU_IDLE;
}

void uart_dfu_slave_reset(uart_dfu_slave_t *s)
{
    const uart_dfu_ops_t *ops = s->ops;
    mbedtls_platform_zeroize(s, sizeof(*s));
    s->ops = ops;
    s->state = UART_DFU_IDLE;
}

int uart_dfu_is_command(const uint8_t *payload, size_t len)
{
    return len >= 1 &&
           payload[0] >= UART_DFU_CMD_BEGIN &&
           payload[0] <= UART_DFU_CMD_ABORT;
}

static size_t reply(uint8_t *resp, uart_dfu_result_t res, uart_dfu_state_t st)
{
    resp[0] = (uint8_t)res;
    resp[1] = (uint8_t)st;
    return 2;
}

static uart_dfu_result_t do_begin(uart_dfu_slave_t *s,
                                  const uint8_t *req, size_t req_len)
{
    if (req_len != UART_DFU_BEGIN_SIZE)
        return UART_DFU_RES_BAD_REQUEST;

    uint32_t update_id  = get_le32(&req[1]);
    uint32_t image_size = get_le32(&req[5]);
    uint8_t  chunk_size = req[9];
    const uint8_t *hash = &req[10];
    const uint8_t *key  = &req[10 + UART_DFU_HASH_SIZE];

    /* Idempotent: a repeated BEGIN for the transfer in progress (e.g. the
     * master lost our response) keeps the chunks received so far. */
    if (s->state == UART_DFU_RECEIVING &&
        s->update_id == update_id &&
        s->image_size == image_size &&
        s->chunk_size == chunk_size &&
        memcmp(s->hash, hash, UART_DFU_HASH_SIZE) == 0 &&
        mbedtls_ct_memcmp(s->image_key, key, UART_KEY_SIZE) == 0)
        return UART_DFU_RES_OK;

    uart_dfu_slave_reset(s);

    uint16_t n = uart_dfu_chunk_count(image_size, chunk_size);

    if (image_size == 0 || n == 0)
        return UART_DFU_RES_BAD_REQUEST;

    if (image_size > s->ops->slot_size)
        return UART_DFU_RES_TOO_LARGE;

    if (s->ops->erase(s->ops->user, image_size) != 0) {
        s->state = UART_DFU_FAILED;
        return UART_DFU_RES_FLASH_ERROR;
    }

    s->update_id  = update_id;
    s->image_size = image_size;
    s->chunk_size = chunk_size;
    s->n_chunks   = n;
    memcpy(s->hash, hash, UART_DFU_HASH_SIZE);
    memcpy(s->image_key, key, UART_KEY_SIZE);
    s->state = UART_DFU_RECEIVING;

    return UART_DFU_RES_OK;
}

static uart_dfu_result_t do_finish(uart_dfu_slave_t *s)
{
    if (s->state == UART_DFU_VERIFIED)
        return UART_DFU_RES_OK;

    if (s->state != UART_DFU_RECEIVING)
        return UART_DFU_RES_BAD_STATE;

    if (s->received != s->n_chunks)
        return UART_DFU_RES_INCOMPLETE;

    /* No more chunks are needed: drop the image key now. */
    mbedtls_platform_zeroize(s->image_key, sizeof(s->image_key));

    mbedtls_sha256_context sha;
    uint8_t digest[UART_DFU_HASH_SIZE];
    uint8_t buf[64];
    uart_dfu_result_t res = UART_DFU_RES_OK;

    mbedtls_sha256_init(&sha);
    if (mbedtls_sha256_starts(&sha, 0) != 0)
        res = UART_DFU_RES_FLASH_ERROR;

    for (size_t off = 0; res == UART_DFU_RES_OK && off < s->image_size; ) {
        size_t n = s->image_size - off;
        if (n > sizeof(buf))
            n = sizeof(buf);
        if (s->ops->read(s->ops->user, off, buf, n) != 0 ||
            mbedtls_sha256_update(&sha, buf, n) != 0)
            res = UART_DFU_RES_FLASH_ERROR;
        off += n;
    }

    if (res == UART_DFU_RES_OK && mbedtls_sha256_finish(&sha, digest) != 0)
        res = UART_DFU_RES_FLASH_ERROR;

    mbedtls_sha256_free(&sha);

    if (res == UART_DFU_RES_OK &&
        mbedtls_ct_memcmp(digest, s->hash, UART_DFU_HASH_SIZE) != 0)
        res = UART_DFU_RES_HASH_MISMATCH;

    if (res == UART_DFU_RES_OK &&
        s->ops->verify_signature(s->ops->user, s->image_size) != 0)
        res = UART_DFU_RES_SIGNATURE_INVALID;

    s->state = (res == UART_DFU_RES_OK) ? UART_DFU_VERIFIED : UART_DFU_FAILED;
    return res;
}

uart_status_t uart_dfu_slave_handle_command(
    uart_dfu_slave_t *s,
    const uint8_t *req, size_t req_len,
    uint8_t *resp, size_t *resp_len)
{
    if (!s || !s->ops || !req || !resp || !resp_len)
        return UART_ERR_ARGUMENT;

    if (!uart_dfu_is_command(req, req_len))
        return UART_ERR_FORMAT;

    if (*resp_len < UART_MAX_PAYLOAD)
        return UART_ERR_BUFFER;

    uart_dfu_result_t res;

    switch (req[0]) {
    case UART_DFU_CMD_BEGIN:
        res = do_begin(s, req, req_len);
        break;

    case UART_DFU_CMD_STATUS: {
        if (req_len != 1) {
            res = UART_DFU_RES_BAD_REQUEST;
            break;
        }
        size_t bytes = (s->state == UART_DFU_RECEIVING)
                     ? (s->n_chunks + 7u) / 8u : 0;
        resp[0] = UART_DFU_RES_OK;
        resp[1] = (uint8_t)s->state;
        put_le32(&resp[2], s->update_id);
        put_le16(&resp[6], (uint16_t)(s->n_chunks - s->received));
        for (size_t i = 0; i < bytes; i++)
            resp[UART_DFU_STATUS_HDR + i] = (uint8_t)~s->bitmap[i];
        /* Clear padding bits past the last chunk. */
        if (bytes && (s->n_chunks % 8))
            resp[UART_DFU_STATUS_HDR + bytes - 1] &=
                (uint8_t)((1u << (s->n_chunks % 8)) - 1);
        *resp_len = UART_DFU_STATUS_HDR + bytes;
        return UART_OK;
    }

    case UART_DFU_CMD_FINISH:
        res = (req_len == 1) ? do_finish(s) : UART_DFU_RES_BAD_REQUEST;
        break;

    case UART_DFU_CMD_ACTIVATE:
        if (req_len != 1)
            res = UART_DFU_RES_BAD_REQUEST;
        else if (s->state != UART_DFU_VERIFIED)
            res = UART_DFU_RES_BAD_STATE;
        else if (s->ops->activate(s->ops->user, s->image_size) != 0)
            res = UART_DFU_RES_ACTIVATE_FAILED;
        else
            res = UART_DFU_RES_OK;
        break;

    case UART_DFU_CMD_ABORT:
        uart_dfu_slave_reset(s);
        res = UART_DFU_RES_OK;
        break;

    default:
        res = UART_DFU_RES_BAD_REQUEST;
        break;
    }

    *resp_len = reply(resp, res, s->state);
    return UART_OK;
}

uart_status_t uart_dfu_slave_handle_chunk(
    uart_dfu_slave_t *s,
    const uint8_t *frame, size_t frame_len)
{
    if (!s || !s->ops || !frame)
        return UART_ERR_ARGUMENT;

    if (s->state != UART_DFU_RECEIVING)
        return UART_ERR_STATE;

    uint8_t data[UART_MAX_PAYLOAD];
    size_t data_len = sizeof(data);
    uint16_t index;

    uart_status_t st = uart_decode_dfu_chunk(s->image_key, s->update_id,
                                             frame, frame_len,
                                             &index, data, &data_len);
    if (st != UART_OK)
        return st;

    if (index >= s->n_chunks || data_len != chunk_len(s, index)) {
        st = UART_ERR_FORMAT;
        goto out;
    }

    /* Duplicate (re-broadcast for another slave): already have it. */
    if (s->bitmap[index / 8] & (1u << (index % 8)))
        goto out;

    if (s->ops->write(s->ops->user, (size_t)index * s->chunk_size,
                      data, data_len) != 0) {
        st = UART_ERR_CRYPTO;   /* flash error; chunk stays missing */
        goto out;
    }

    s->bitmap[index / 8] |= (uint8_t)(1u << (index % 8));
    s->received++;

out:
    mbedtls_platform_zeroize(data, sizeof(data));
    return st;
}

/* ---- Master ---------------------------------------------------------- */

uart_status_t uart_dfu_build_begin(
    uint32_t update_id, uint32_t image_size, uint8_t chunk_size,
    const uint8_t hash[UART_DFU_HASH_SIZE],
    const uint8_t image_key[UART_KEY_SIZE],
    uint8_t *out, size_t *out_len)
{
    if (!hash || !image_key || !out || !out_len)
        return UART_ERR_ARGUMENT;

    if (uart_dfu_chunk_count(image_size, chunk_size) == 0)
        return UART_ERR_LENGTH;

    if (*out_len < UART_DFU_BEGIN_SIZE)
        return UART_ERR_BUFFER;

    out[0] = UART_DFU_CMD_BEGIN;
    put_le32(&out[1], update_id);
    put_le32(&out[5], image_size);
    out[9] = chunk_size;
    memcpy(&out[10], hash, UART_DFU_HASH_SIZE);
    memcpy(&out[10 + UART_DFU_HASH_SIZE], image_key, UART_KEY_SIZE);

    *out_len = UART_DFU_BEGIN_SIZE;
    return UART_OK;
}

uart_status_t uart_dfu_parse_status(
    const uint8_t *resp, size_t resp_len, uart_dfu_status_t *out)
{
    if (!resp || !out)
        return UART_ERR_ARGUMENT;

    if (resp_len < UART_DFU_STATUS_HDR)
        return UART_ERR_LENGTH;

    out->result     = (uart_dfu_result_t)resp[0];
    out->state      = (uart_dfu_state_t)resp[1];
    out->update_id  = get_le32(&resp[2]);
    out->missing    = get_le16(&resp[6]);
    out->bitmap     = &resp[UART_DFU_STATUS_HDR];
    out->bitmap_len = resp_len - UART_DFU_STATUS_HDR;
    return UART_OK;
}
