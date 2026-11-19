#include "uart_frame.h"

#include <string.h>
#include "mbedtls/ccm.h"
#include "mbedtls/platform_util.h"

#define UART_NONCE_SIZE 13
#define UART_EXT_MAX    UART_SEQ_SIZE

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

/* Nonce = TYPE | ADDR | tail | 0x00 padding */
static void build_nonce(uint8_t nonce[UART_NONCE_SIZE], uint8_t type,
                        uint8_t addr, const uint8_t *tail, size_t tail_len)
{
    memset(nonce, 0, UART_NONCE_SIZE);
    nonce[0] = type;
    nonce[1] = addr;
    memcpy(&nonce[2], tail, tail_len);
}

/* ---- Generic seal / open --------------------------------------------- */

static uart_status_t seal(
    const uint8_t *key, uint8_t type, uint8_t addr,
    const uint8_t *ext, size_t ext_len,
    const uint8_t nonce[UART_NONCE_SIZE],
    const uint8_t *payload, size_t payload_len,
    uint8_t *dst, size_t *dst_len)
{
    if (!key || (!payload && payload_len) || !dst || !dst_len)
        return UART_ERR_ARGUMENT;

    if (payload_len > UART_MAX_PAYLOAD)
        return UART_ERR_LENGTH;

    size_t required = UART_HEADER_SIZE + ext_len + payload_len + UART_TAG_SIZE;

    if (*dst_len < required)
        return UART_ERR_BUFFER;

    dst[0] = UART_SOF;
    dst[1] = addr;
    dst[2] = type;
    dst[3] = (uint8_t)payload_len;
    if (ext_len)
        memcpy(&dst[UART_HEADER_SIZE], ext, ext_len);

    /* AAD = ADDR | TYPE | LEN | EXT */
    const uint8_t *aad = &dst[1];
    size_t aad_len = 3 + ext_len;

    uint8_t *ct  = &dst[UART_HEADER_SIZE + ext_len];
    uint8_t *tag = ct + payload_len;

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    uart_status_t st = UART_OK;

    if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, UART_KEY_SIZE * 8) != 0 ||
        mbedtls_ccm_encrypt_and_tag(&ctx, payload_len,
                                    nonce, UART_NONCE_SIZE,
                                    aad, aad_len,
                                    payload, ct,
                                    tag, UART_TAG_SIZE) != 0) {
        mbedtls_platform_zeroize(dst, required);
        st = UART_ERR_CRYPTO;
    } else {
        *dst_len = required;
    }

    mbedtls_ccm_free(&ctx);
    return st;
}

/*
 * Structural checks only (no crypto). On success *len is the payload length
 * and the EXT field starts at src + UART_HEADER_SIZE.
 */
static uart_status_t check_header(
    uint8_t type, uint8_t addr, size_t ext_len,
    const uint8_t *src, size_t src_len, size_t *len)
{
    if (!src)
        return UART_ERR_ARGUMENT;

    if (src_len < UART_HEADER_SIZE)
        return UART_ERR_LENGTH;

    if (src[0] != UART_SOF)
        return UART_ERR_FORMAT;

    /* Cheap address filter before any crypto: on a broadcast bus most
     * frames are for someone else. */
    if (src[1] != addr)
        return UART_ERR_ADDR;

    if (src[2] != type)
        return UART_ERR_FORMAT;

    *len = src[3];

    if (src_len != UART_HEADER_SIZE + ext_len + *len + UART_TAG_SIZE)
        return UART_ERR_LENGTH;

    return UART_OK;
}

static uart_status_t open_frame(
    const uint8_t *key, size_t ext_len,
    const uint8_t nonce[UART_NONCE_SIZE],
    const uint8_t *src, size_t len,
    uint8_t *payload, size_t *payload_len)
{
    if (!key || !payload_len || (len && !payload))
        return UART_ERR_ARGUMENT;

    if (*payload_len < len)
        return UART_ERR_BUFFER;

    const uint8_t *aad = &src[1];
    size_t aad_len = 3 + ext_len;

    const uint8_t *ct  = &src[UART_HEADER_SIZE + ext_len];
    const uint8_t *tag = ct + len;

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    uart_status_t st = UART_OK;

    if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, UART_KEY_SIZE * 8) != 0) {
        st = UART_ERR_CRYPTO;
    } else {
        int ret = mbedtls_ccm_auth_decrypt(&ctx, len,
                                           nonce, UART_NONCE_SIZE,
                                           aad, aad_len,
                                           ct, payload,
                                           tag, UART_TAG_SIZE);
        if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED)
            st = UART_ERR_AUTH;
        else if (ret != 0)
            st = UART_ERR_CRYPTO;
    }

    mbedtls_ccm_free(&ctx);

    if (st != UART_OK) {
        /* Never leave unauthenticated plaintext in the caller's buffer. */
        if (len)
            mbedtls_platform_zeroize(payload, len);
        return st;
    }

    *payload_len = len;
    return UART_OK;
}

/* ---- Public API ------------------------------------------------------ */

uint8_t uart_frame_type(const uint8_t *src, size_t src_len)
{
    if (!src || src_len < UART_HEADER_SIZE || src[0] != UART_SOF)
        return 0;
    return src[2];
}

uart_status_t uart_encode_request(
    const uint8_t *key, uint8_t addr,
    const uint8_t *payload, size_t payload_len,
    uint32_t seq, uint8_t *dst, size_t *dst_len)
{
    if (addr == UART_ADDR_BROADCAST)
        return UART_ERR_ARGUMENT;

    uint8_t ext[UART_SEQ_SIZE];
    put_le32(ext, seq);

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_REQUEST, addr, ext, sizeof(ext));

    return seal(key, UART_TYPE_REQUEST, addr, ext, sizeof(ext), nonce,
                payload, payload_len, dst, dst_len);
}

uart_status_t uart_decode_request(
    const uint8_t *key, uint8_t addr,
    const uint8_t *src, size_t src_len,
    uint8_t *payload, size_t *payload_len, uint32_t *seq)
{
    size_t len;

    if (!seq || addr == UART_ADDR_BROADCAST)
        return UART_ERR_ARGUMENT;

    uart_status_t st = check_header(UART_TYPE_REQUEST, addr, UART_SEQ_SIZE,
                                    src, src_len, &len);
    if (st != UART_OK)
        return st;

    const uint8_t *ext = &src[UART_HEADER_SIZE];

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_REQUEST, addr, ext, UART_SEQ_SIZE);

    st = open_frame(key, UART_SEQ_SIZE, nonce, src, len, payload, payload_len);
    if (st == UART_OK)
        *seq = get_le32(ext);

    return st;
}

uart_status_t uart_encode_response(
    const uint8_t *key, uint8_t addr,
    const uint8_t *payload, size_t payload_len,
    uint32_t seq, uint8_t *dst, size_t *dst_len)
{
    if (addr == UART_ADDR_BROADCAST)
        return UART_ERR_ARGUMENT;

    uint8_t tail[UART_SEQ_SIZE];
    put_le32(tail, seq);

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_RESPONSE, addr, tail, sizeof(tail));

    return seal(key, UART_TYPE_RESPONSE, addr, NULL, 0, nonce,
                payload, payload_len, dst, dst_len);
}

uart_status_t uart_decode_response(
    const uint8_t *key, uint8_t addr,
    const uint8_t *src, size_t src_len,
    uint32_t seq, uint8_t *payload, size_t *payload_len)
{
    size_t len;

    if (addr == UART_ADDR_BROADCAST)
        return UART_ERR_ARGUMENT;

    uart_status_t st = check_header(UART_TYPE_RESPONSE, addr, 0,
                                    src, src_len, &len);
    if (st != UART_OK)
        return st;

    uint8_t tail[UART_SEQ_SIZE];
    put_le32(tail, seq);

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_RESPONSE, addr, tail, sizeof(tail));

    return open_frame(key, 0, nonce, src, len, payload, payload_len);
}

uart_status_t uart_encode_dfu_chunk(
    const uint8_t *image_key, uint32_t update_id, uint16_t index,
    const uint8_t *data, size_t data_len,
    uint8_t *dst, size_t *dst_len)
{
    uint8_t ext[UART_INDEX_SIZE];
    put_le16(ext, index);

    uint8_t tail[4 + UART_INDEX_SIZE];
    put_le32(tail, update_id);
    put_le16(&tail[4], index);

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_DFU_CHUNK, UART_ADDR_BROADCAST,
                tail, sizeof(tail));

    return seal(image_key, UART_TYPE_DFU_CHUNK, UART_ADDR_BROADCAST,
                ext, sizeof(ext), nonce, data, data_len, dst, dst_len);
}

uart_status_t uart_decode_dfu_chunk(
    const uint8_t *image_key, uint32_t update_id,
    const uint8_t *src, size_t src_len,
    uint16_t *index, uint8_t *data, size_t *data_len)
{
    size_t len;

    if (!index)
        return UART_ERR_ARGUMENT;

    uart_status_t st = check_header(UART_TYPE_DFU_CHUNK, UART_ADDR_BROADCAST,
                                    UART_INDEX_SIZE, src, src_len, &len);
    if (st != UART_OK)
        return st;

    uint16_t idx = get_le16(&src[UART_HEADER_SIZE]);

    uint8_t tail[4 + UART_INDEX_SIZE];
    put_le32(tail, update_id);
    put_le16(&tail[4], idx);

    uint8_t nonce[UART_NONCE_SIZE];
    build_nonce(nonce, UART_TYPE_DFU_CHUNK, UART_ADDR_BROADCAST,
                tail, sizeof(tail));

    st = open_frame(image_key, UART_INDEX_SIZE, nonce, src, len, data, data_len);
    if (st == UART_OK)
        *index = idx;

    return st;
}
