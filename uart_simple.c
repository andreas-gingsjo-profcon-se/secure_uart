#include "uart_simple.h"

#include <string.h>
#include "mbedtls/ccm.h"
#include "mbedtls/platform_util.h"

#define NONCE_SIZE    13
#define AAD_MAX       (2 + 1 + UART_SIMPLE_MAX_BODY + 1 + UART_SIMPLE_MAX_BODY)
#define BBRAM_MAGIC   0x53554152u   /* "SUAR" */
#define NONCE_ANNOUNCE 4            /* nonce TYPE for ANNOUNCE (not a CTRL type) */

/* ---- Helpers --------------------------------------------------------- */

/* CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). */
static uint16_t crc16(const uint8_t *p, size_t n)
{
    uint16_t crc = 0xFFFF;
    while (n--) {
        crc ^= (uint16_t)(*p++) << 8;
        for (int i = 0; i < 8; i++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p)
{
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint8_t ctrl(uart_simple_type_t type, size_t len)
{
    return (uint8_t)(((unsigned)type << 6) | (len & 0x3F));
}

static void build_nonce(uint8_t nonce[NONCE_SIZE], uint8_t type,
                        uint8_t addr, uint32_t epoch, uint32_t seq)
{
    memset(nonce, 0, NONCE_SIZE);
    nonce[0] = type;
    nonce[1] = addr;
    put_le32(&nonce[2], epoch);
    put_le32(&nonce[6], seq);
}

/* AAD = ADDR | CTRL | len(s) | s [| len(c) | c] */
static size_t build_aad(uint8_t aad[AAD_MAX], uint8_t addr, uint8_t ctl,
                        const uint8_t *s, size_t s_len,
                        const uint8_t *c, size_t c_len, int with_cmd)
{
    size_t n = 0;
    aad[n++] = addr;
    aad[n++] = ctl;
    aad[n++] = (uint8_t)s_len;
    memcpy(&aad[n], s, s_len);
    n += s_len;
    if (with_cmd) {
        aad[n++] = (uint8_t)c_len;
        memcpy(&aad[n], c, c_len);
        n += c_len;
    }
    return n;
}

/* Which trailer a frame carries. */
static size_t trailer_size(unsigned type, size_t body_len)
{
    if (type == UART_SIMPLE_TYPE_READ)
        return body_len == 0 ? UART_SIMPLE_CRC_SIZE : UART_SIMPLE_TAG_SIZE;
    if (type == UART_SIMPLE_TYPE_STATUS)
        return UART_SIMPLE_CRC_SIZE;
    return UART_SIMPLE_TAG_SIZE;
}

/* Common header check. Returns body length in *body_len. */
static uart_simple_status_t parse(const uint8_t *f, size_t len,
                                  uart_simple_type_t type, uint8_t addr,
                                  size_t *body_len)
{
    if (!f)
        return UART_SIMPLE_ERR_ARGUMENT;
    if (len < UART_SIMPLE_HDR_SIZE)
        return UART_SIMPLE_ERR_LENGTH;
    if (f[0] != UART_SIMPLE_SOF)
        return UART_SIMPLE_ERR_FORMAT;
    if (f[1] != addr)
        return UART_SIMPLE_ERR_ADDR;
    if ((f[2] >> 6) != (unsigned)type)
        return UART_SIMPLE_ERR_FORMAT;

    size_t bl = f[2] & 0x3F;
    size_t trailer = trailer_size(type, bl);

    if (type == UART_SIMPLE_TYPE_READ && bl != 0 && bl != UART_SIMPLE_ANNOUNCE_BODY)
        return UART_SIMPLE_ERR_LENGTH;

    if (len != UART_SIMPLE_HDR_SIZE + bl + trailer)
        return UART_SIMPLE_ERR_LENGTH;

    if (trailer == UART_SIMPLE_CRC_SIZE) {
        uint16_t c = crc16(&f[1], 2 + bl);
        size_t o = UART_SIMPLE_HDR_SIZE + bl;
        if (f[o] != (uint8_t)(c >> 8) || f[o + 1] != (uint8_t)c)
            return UART_SIMPLE_ERR_CRC;
    }

    *body_len = bl;
    return UART_SIMPLE_OK;
}

/* Plain frame with CRC (READ / STATUS). */
static uart_simple_status_t build_plain(uart_simple_type_t type, uint8_t addr,
                                        const uint8_t *body, size_t body_len,
                                        uint8_t *dst, size_t *dst_len)
{
    size_t need = UART_SIMPLE_HDR_SIZE + body_len + UART_SIMPLE_CRC_SIZE;

    if (!dst || !dst_len || (body_len && !body))
        return UART_SIMPLE_ERR_ARGUMENT;
    if (body_len > UART_SIMPLE_MAX_BODY)
        return UART_SIMPLE_ERR_LENGTH;
    if (*dst_len < need)
        return UART_SIMPLE_ERR_BUFFER;

    dst[0] = UART_SIMPLE_SOF;
    dst[1] = addr;
    dst[2] = ctrl(type, body_len);
    if (body_len)
        memcpy(&dst[3], body, body_len);

    uint16_t c = crc16(&dst[1], 2 + body_len);
    dst[3 + body_len] = (uint8_t)(c >> 8);
    dst[4 + body_len] = (uint8_t)c;

    *dst_len = need;
    return UART_SIMPLE_OK;
}

/* CCM seal with an explicit nonce and AAD. Writes ciphertext + tag. */
static int ccm_seal(const uint8_t *key, const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *pt, size_t len, uint8_t *ct, uint8_t *tag)
{
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key,
                                 UART_SIMPLE_KEY_SIZE * 8);
    if (ret == 0)
        ret = mbedtls_ccm_encrypt_and_tag(&ctx, len, nonce, NONCE_SIZE,
                                          aad, aad_len, pt, ct,
                                          tag, UART_SIMPLE_TAG_SIZE);
    mbedtls_ccm_free(&ctx);
    return ret;
}

/* CCM open. Returns 0, MBEDTLS_ERR_CCM_AUTH_FAILED or another error. */
static int ccm_open(const uint8_t *key, const uint8_t nonce[NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t len, uint8_t *pt,
                    const uint8_t *tag)
{
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key,
                                 UART_SIMPLE_KEY_SIZE * 8);
    if (ret == 0)
        ret = mbedtls_ccm_auth_decrypt(&ctx, len, nonce, NONCE_SIZE,
                                       aad, aad_len, ct, pt,
                                       tag, UART_SIMPLE_TAG_SIZE);
    mbedtls_ccm_free(&ctx);
    return ret;
}

int uart_simple_frame_type(const uint8_t *f, size_t len)
{
    if (!f || len < UART_SIMPLE_HDR_SIZE || f[0] != UART_SIMPLE_SOF)
        return -1;
    return f[2] >> 6;
}

int uart_simple_frame_addr(const uint8_t *f, size_t len)
{
    if (!f || len < UART_SIMPLE_HDR_SIZE || f[0] != UART_SIMPLE_SOF)
        return -1;
    return f[1];
}

/* ---- Master: epoch --------------------------------------------------- */

static uint32_t bb_check(const uart_simple_bbram_t *bb)
{
    return ~(bb->magic ^ bb->epoch ^ (bb->n_slaves * 0x9E3779B9u));
}

uart_simple_status_t uart_simple_epoch_bump(uart_simple_epoch_t *e)
{
    if (!e || !e->ops || !e->bb)
        return UART_SIMPLE_ERR_ARGUMENT;

    uart_simple_bbram_t *bb = e->bb;

    /* 1. Invalidate: a crash from here on forces another bump at boot. */
    bb->magic = 0;

    /* 2. Burn the epoch in hardware BEFORE any SEQ can be reused. */
    uint32_t ne;
    if (e->ops->increment(e->ops->user, &ne) != 0 || ne <= e->epoch)
        return UART_SIMPLE_ERR_EPOCH;

    /* 3. Fresh SEQ space, then re-validate the header. */
    for (uint32_t i = 0; i < bb->n_slaves; i++)
        bb->seq[i] = 0;
    bb->epoch = ne;
    bb->check = 0;
    bb->magic = BBRAM_MAGIC;
    bb->check = bb_check(bb);

    e->epoch = ne;
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_epoch_boot(
    uart_simple_epoch_t *e, const uart_simple_counter_ops_t *ops,
    uart_simple_bbram_t *bb, uint32_t n_slaves, int *bumped)
{
    if (!e || !ops || !ops->read || !ops->increment || !bb)
        return UART_SIMPLE_ERR_ARGUMENT;

    e->ops = ops;
    e->bb = bb;

    uint32_t hw;
    if (ops->read(ops->user, &hw) != 0)
        return UART_SIMPLE_ERR_EPOCH;

    e->epoch = hw;
    if (bumped)
        *bumped = 0;

    if (bb->magic == BBRAM_MAGIC &&
        bb->n_slaves == n_slaves &&
        bb->epoch == hw &&
        bb->check == bb_check(bb))
        return UART_SIMPLE_OK;          /* BBRAM intact: resume */

    /* BBRAM lost or inconsistent: every SEQ might have been used. */
    bb->magic = 0;
    bb->n_slaves = n_slaves;
    if (bumped)
        *bumped = 1;
    return uart_simple_epoch_bump(e);
}

/* ---- Master: per slave ----------------------------------------------- */

void uart_simple_master_init(uart_simple_master_t *m, const uint8_t *key,
                             uint8_t addr, uart_simple_epoch_t *ep,
                             uint32_t slot)
{
    memset(m, 0, sizeof(*m));
    m->key = key;
    m->addr = addr;
    m->ep = ep;
    m->slot = slot;
}

/* Take the next SEQ for this slave. Persistent store happens first. */
static uart_simple_status_t next_seq(uart_simple_master_t *m, uint32_t *seq)
{
    if (!m->ep || !m->ep->bb || m->slot >= m->ep->bb->n_slaves)
        return UART_SIMPLE_ERR_ARGUMENT;

    uint32_t *slot = &m->ep->bb->seq[m->slot];
    if (*slot == UINT32_MAX)
        return UART_SIMPLE_ERR_SEQ;

    *seq = ++(*slot);
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_master_build_read(
    uart_simple_master_t *m, uint8_t *dst, size_t *dst_len)
{
    if (!m)
        return UART_SIMPLE_ERR_ARGUMENT;

    m->status_valid = 0;
    return build_plain(UART_SIMPLE_TYPE_READ, m->addr, NULL, 0, dst, dst_len);
}

uart_simple_status_t uart_simple_master_build_announce(
    uart_simple_master_t *m, uint8_t *dst, size_t *dst_len)
{
    size_t need = UART_SIMPLE_HDR_SIZE + UART_SIMPLE_ANNOUNCE_BODY +
                  UART_SIMPLE_TAG_SIZE;

    if (!m || !dst || !dst_len)
        return UART_SIMPLE_ERR_ARGUMENT;
    if (*dst_len < need)
        return UART_SIMPLE_ERR_BUFFER;

    uint32_t seq;
    uart_simple_status_t st = next_seq(m, &seq);
    if (st != UART_SIMPLE_OK)
        return st;

    uint32_t epoch = m->ep->epoch;

    dst[0] = UART_SIMPLE_SOF;
    dst[1] = m->addr;
    dst[2] = ctrl(UART_SIMPLE_TYPE_READ, UART_SIMPLE_ANNOUNCE_BODY);
    put_le32(&dst[3], epoch);
    put_le32(&dst[7], seq);

    uint8_t nonce[NONCE_SIZE];
    build_nonce(nonce, NONCE_ANNOUNCE, m->addr, epoch, seq);

    /* AAD = ADDR | CTRL | EPOCH | SEQ, no ciphertext */
    if (ccm_seal(m->key, nonce, &dst[1], 2 + UART_SIMPLE_ANNOUNCE_BODY,
                 NULL, 0, NULL, &dst[3 + UART_SIMPLE_ANNOUNCE_BODY]) != 0) {
        mbedtls_platform_zeroize(dst, need);
        return UART_SIMPLE_ERR_CRYPTO;
    }

    m->status_valid = 0;
    *dst_len = need;
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_master_handle_status(
    uart_simple_master_t *m, const uint8_t *frame, size_t len)
{
    size_t bl;

    if (!m)
        return UART_SIMPLE_ERR_ARGUMENT;

    uart_simple_status_t st = parse(frame, len, UART_SIMPLE_TYPE_STATUS,
                                    m->addr, &bl);
    if (st != UART_SIMPLE_OK)
        return st;

    memcpy(m->status, &frame[3], bl);
    m->status_len = (uint8_t)bl;
    m->status_valid = 1;
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_master_build_cmd(
    uart_simple_master_t *m, const uint8_t *cmd, size_t cmd_len,
    uint8_t *dst, size_t *dst_len)
{
    size_t need = UART_SIMPLE_HDR_SIZE + cmd_len + UART_SIMPLE_TAG_SIZE;

    if (!m || !dst || !dst_len || (cmd_len && !cmd))
        return UART_SIMPLE_ERR_ARGUMENT;
    if (cmd_len > UART_SIMPLE_MAX_BODY)
        return UART_SIMPLE_ERR_LENGTH;
    if (*dst_len < need)
        return UART_SIMPLE_ERR_BUFFER;
    if (!m->status_valid)
        return UART_SIMPLE_ERR_STATE;

    /* Consume the SEQ in persistent storage BEFORE using it. */
    uint32_t seq;
    uart_simple_status_t st = next_seq(m, &seq);
    if (st != UART_SIMPLE_OK)
        return st;

    uint32_t epoch = m->ep->epoch;

    dst[0] = UART_SIMPLE_SOF;
    dst[1] = m->addr;
    dst[2] = ctrl(UART_SIMPLE_TYPE_CMD, cmd_len);

    uint8_t nonce[NONCE_SIZE];
    uint8_t aad[AAD_MAX];
    build_nonce(nonce, UART_SIMPLE_TYPE_CMD, m->addr, epoch, seq);
    size_t aad_len = build_aad(aad, m->addr, dst[2],
                               m->status, m->status_len, NULL, 0, 0);

    if (ccm_seal(m->key, nonce, aad, aad_len, cmd, cmd_len,
                 &dst[3], &dst[3 + cmd_len]) != 0) {
        mbedtls_platform_zeroize(dst, need);
        return UART_SIMPLE_ERR_CRYPTO;
    }

    if (cmd_len)
        memcpy(m->cmd, cmd, cmd_len);
    m->cmd_len = (uint8_t)cmd_len;
    m->cmd_epoch = epoch;
    m->cmd_seq = seq;
    m->cmd_pending = 1;
    m->status_valid = 0;   /* one command per READ */

    *dst_len = need;
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_master_handle_ack(
    uart_simple_master_t *m, const uint8_t *frame, size_t len,
    uart_simple_result_t *result)
{
    size_t bl;

    if (!m || !result)
        return UART_SIMPLE_ERR_ARGUMENT;
    if (!m->cmd_pending)
        return UART_SIMPLE_ERR_STATE;

    uart_simple_status_t st = parse(frame, len, UART_SIMPLE_TYPE_ACK,
                                    m->addr, &bl);
    if (st != UART_SIMPLE_OK)
        return st;
    if (bl != 1)
        return UART_SIMPLE_ERR_LENGTH;

    uint8_t nonce[NONCE_SIZE];
    uint8_t aad[AAD_MAX];
    build_nonce(nonce, UART_SIMPLE_TYPE_ACK, m->addr, m->cmd_epoch, m->cmd_seq);
    size_t aad_len = build_aad(aad, m->addr, frame[2],
                               m->status, m->status_len,
                               m->cmd, m->cmd_len, 1);

    uint8_t r = 0;
    int ret = ccm_open(m->key, nonce, aad, aad_len, &frame[3], 1, &r, &frame[4]);

    if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED)
        return UART_SIMPLE_ERR_AUTH;
    if (ret != 0)
        return UART_SIMPLE_ERR_CRYPTO;

    m->cmd_pending = 0;
    *result = (uart_simple_result_t)r;
    return UART_SIMPLE_OK;
}

/* ---- Slave ----------------------------------------------------------- */

void uart_simple_slave_init(uart_simple_slave_t *s, const uint8_t *key,
                            uint8_t addr, uint32_t stored_epoch,
                            int fresh_key,
                            uart_simple_persist_fn persist, void *persist_user)
{
    memset(s, 0, sizeof(*s));
    s->key = key;
    s->addr = addr;
    s->epoch = stored_epoch;
    s->last_seq = 0;
    s->seq_valid = fresh_key ? 1 : 0;
    s->persist = persist;
    s->persist_user = persist_user;
}

/* Move to a new epoch: durable BEFORE anything is acted on. */
static uart_simple_status_t enter_epoch(uart_simple_slave_t *s,
                                        uint32_t epoch, uint32_t last_seq)
{
    if (epoch != s->epoch) {
        if (!s->persist || s->persist(s->persist_user, epoch) != 0)
            return UART_SIMPLE_ERR_PERSIST;
        s->epoch = epoch;
    }
    s->last_seq = last_seq;
    s->seq_valid = 1;
    return UART_SIMPLE_OK;
}

static uart_simple_status_t handle_announce(uart_simple_slave_t *s,
                                            const uint8_t *frame)
{
    uint32_t epoch = get_le32(&frame[3]);
    uint32_t seq   = get_le32(&frame[7]);

    /* Only strictly newer epochs: an old ANNOUNCE can never rewind us,
     * and after a reboot the stored epoch stays refused. */
    if (epoch <= s->epoch)
        return UART_SIMPLE_ERR_AUTH;

    uint8_t nonce[NONCE_SIZE];
    build_nonce(nonce, NONCE_ANNOUNCE, s->addr, epoch, seq);

    int ret = ccm_open(s->key, nonce, &frame[1], 2 + UART_SIMPLE_ANNOUNCE_BODY,
                       NULL, 0, NULL, &frame[3 + UART_SIMPLE_ANNOUNCE_BODY]);
    if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED)
        return UART_SIMPLE_ERR_AUTH;
    if (ret != 0)
        return UART_SIMPLE_ERR_CRYPTO;

    return enter_epoch(s, epoch, seq);
}

uart_simple_status_t uart_simple_slave_handle_read(
    uart_simple_slave_t *s, const uint8_t *frame, size_t len,
    const uint8_t *status, size_t status_len,
    uint8_t *dst, size_t *dst_len)
{
    size_t bl;

    if (!s || (status_len && !status))
        return UART_SIMPLE_ERR_ARGUMENT;
    if (status_len > UART_SIMPLE_MAX_BODY)
        return UART_SIMPLE_ERR_LENGTH;

    uart_simple_status_t st = parse(frame, len, UART_SIMPLE_TYPE_READ,
                                    s->addr, &bl);
    if (st != UART_SIMPLE_OK)
        return st;

    if (bl == UART_SIMPLE_ANNOUNCE_BODY) {
        st = handle_announce(s, frame);
        if (st != UART_SIMPLE_OK)
            return st;
    }

    st = build_plain(UART_SIMPLE_TYPE_STATUS, s->addr, status, status_len,
                     dst, dst_len);
    if (st != UART_SIMPLE_OK)
        return st;

    /* READ has no side effects except refreshing the snapshot. */
    if (status_len)
        memcpy(s->snap, status, status_len);
    s->snap_len = (uint8_t)status_len;
    s->snap_valid = 1;
    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_slave_handle_cmd(
    uart_simple_slave_t *s, const uint8_t *frame, size_t len,
    const uint8_t *current_status, size_t current_status_len,
    uint8_t *cmd_out, size_t *cmd_out_len)
{
    size_t bl;

    if (!s || !cmd_out || !cmd_out_len ||
        (current_status_len && !current_status))
        return UART_SIMPLE_ERR_ARGUMENT;

    uart_simple_status_t st = parse(frame, len, UART_SIMPLE_TYPE_CMD,
                                    s->addr, &bl);
    if (st != UART_SIMPLE_OK)
        return st;
    if (*cmd_out_len < bl)
        return UART_SIMPLE_ERR_BUFFER;
    if (!s->snap_valid)
        return UART_SIMPLE_ERR_STATE;

    uint8_t aad[AAD_MAX];
    size_t aad_len = build_aad(aad, s->addr, frame[2],
                               s->snap, s->snap_len, NULL, 0, 0);

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, s->key,
                           UART_SIMPLE_KEY_SIZE * 8) != 0) {
        mbedtls_ccm_free(&ctx);
        return UART_SIMPLE_ERR_CRYPTO;
    }

    /*
     * Candidate (epoch, seq) pairs:
     *   k = 0: current epoch, last_seq+1 .. +W   (only if SEQ state valid)
     *   k > 0: epoch+k, 1 .. W                   (master bumped)
     */
    uint32_t got_epoch = 0, got_seq = 0;
    int found = 0;

    for (uint32_t k = 0; k <= UART_SIMPLE_EPOCH_LOOKAHEAD && !found; k++) {
        if (k == 0 && !s->seq_valid)
            continue;
        if (s->epoch > UINT32_MAX - k)
            break;
        uint32_t ep   = s->epoch + k;
        uint32_t base = (k == 0) ? s->last_seq : 0;

        for (uint32_t i = 1; i <= UART_SIMPLE_SEQ_WINDOW; i++) {
            if (base > UINT32_MAX - i)
                break;
            uint8_t nonce[NONCE_SIZE];
            build_nonce(nonce, UART_SIMPLE_TYPE_CMD, s->addr, ep, base + i);
            int ret = mbedtls_ccm_auth_decrypt(&ctx, bl, nonce, NONCE_SIZE,
                                               aad, aad_len, &frame[3],
                                               cmd_out, &frame[3 + bl],
                                               UART_SIMPLE_TAG_SIZE);
            if (ret == 0) {
                got_epoch = ep;
                got_seq = base + i;
                found = 1;
                break;
            }
            if (ret != MBEDTLS_ERR_CCM_AUTH_FAILED) {
                mbedtls_ccm_free(&ctx);
                return UART_SIMPLE_ERR_CRYPTO;
            }
        }
    }
    mbedtls_ccm_free(&ctx);

    if (!found)
        return UART_SIMPLE_ERR_AUTH;

    /* New epoch must be durable before we act on anything in it. */
    st = enter_epoch(s, got_epoch, got_seq);
    if (st != UART_SIMPLE_OK) {
        mbedtls_platform_zeroize(cmd_out, bl);
        return st;
    }

    /* Authentic: SEQ is consumed even if we end up not executing, so this
     * CMD can never be replayed later when the status matches again. */
    s->snap_valid = 0;

    memcpy(s->cmd, cmd_out, bl);
    s->cmd_len = (uint8_t)bl;
    memcpy(s->ack_snap, s->snap, s->snap_len);
    s->ack_snap_len = s->snap_len;
    s->cmd_epoch = got_epoch;
    s->cmd_seq = got_seq;
    s->ack_pending = 1;
    *cmd_out_len = bl;

    /* Atomic RMW: refuse if the status moved since the snapshot. */
    if (current_status_len != s->snap_len ||
        memcmp(current_status, s->snap, s->snap_len) != 0) {
        mbedtls_platform_zeroize(cmd_out, bl);
        *cmd_out_len = 0;
        return UART_SIMPLE_ERR_STALE;
    }

    return UART_SIMPLE_OK;
}

uart_simple_status_t uart_simple_slave_build_ack(
    uart_simple_slave_t *s, uart_simple_result_t result,
    uint8_t *dst, size_t *dst_len)
{
    size_t need = UART_SIMPLE_HDR_SIZE + 1 + UART_SIMPLE_TAG_SIZE;

    if (!s || !dst || !dst_len)
        return UART_SIMPLE_ERR_ARGUMENT;
    if (!s->ack_pending)
        return UART_SIMPLE_ERR_STATE;
    if (*dst_len < need)
        return UART_SIMPLE_ERR_BUFFER;

    dst[0] = UART_SIMPLE_SOF;
    dst[1] = s->addr;
    dst[2] = ctrl(UART_SIMPLE_TYPE_ACK, 1);

    uint8_t nonce[NONCE_SIZE];
    uint8_t aad[AAD_MAX];
    build_nonce(nonce, UART_SIMPLE_TYPE_ACK, s->addr, s->cmd_epoch, s->cmd_seq);
    size_t aad_len = build_aad(aad, s->addr, dst[2],
                               s->ack_snap, s->ack_snap_len,
                               s->cmd, s->cmd_len, 1);

    uint8_t r = (uint8_t)result;
    int ret = ccm_seal(s->key, nonce, aad, aad_len, &r, 1, &dst[3], &dst[4]);

    /* Exactly one ACK per (epoch, SEQ): nonce uniqueness. */
    s->ack_pending = 0;
    mbedtls_platform_zeroize(s->cmd, sizeof(s->cmd));

    if (ret != 0) {
        mbedtls_platform_zeroize(dst, need);
        return UART_SIMPLE_ERR_CRYPTO;
    }

    *dst_len = need;
    return UART_SIMPLE_OK;
}
