/*
 * Broadcast DFU simulation: one master, three slaves on a lossy shared bus.
 *
 * The "signature" in this demo is a placeholder trailer (magic + version)
 * so the flow can be exercised. Replace demo_verify_signature() with the
 * real check of the vendor signature in your DFU file format.
 */
#include "uart_frame.h"
#include "uart_dfu.h"

#include <stdio.h>
#include <string.h>
#include "mbedtls/sha256.h"

static const uint8_t system_key[16] = {
    0xA3, 0x7F, 0x19, 0xC2,
    0xE8, 0x4B, 0x60, 0x5D,
    0x91, 0xF0, 0x3A, 0x7C,
    0x52, 0xD8, 0xB6, 0x41
};

#define N_SLAVES   3
#define SLOT_SIZE  (64 * 1024)
#define BAUD       4800

/* ---- Demo DFU file: body | "DSIG" | version (4, LE) ------------------ */

#define TRAILER_SIZE 8

static uint32_t rng_state = 0x1234567;

static uint32_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static size_t make_dfu_file(uint8_t *buf, size_t body_len, uint32_t version,
                            int sign)
{
    for (size_t i = 0; i < body_len; i++)
        buf[i] = (uint8_t)rng();
    memcpy(&buf[body_len], sign ? "DSIG" : "XXXX", 4);
    buf[body_len + 4] = (uint8_t)version;
    buf[body_len + 5] = (uint8_t)(version >> 8);
    buf[body_len + 6] = (uint8_t)(version >> 16);
    buf[body_len + 7] = (uint8_t)(version >> 24);
    return body_len + TRAILER_SIZE;
}

/* ---- Simulated slave ------------------------------------------------- */

typedef struct {
    uint8_t addr;
    uint32_t last_seq;          /* RAM only: lost on reboot (needs SYNC) */
    uint32_t installed_version;
    int drop_percent;           /* bus loss seen by this slave */
    uart_dfu_ops_t ops;
    uart_dfu_slave_t dfu;
    uint8_t slot[SLOT_SIZE];
} slave_t;

static slave_t slaves[N_SLAVES];

static int flash_erase(void *u, size_t size)
{
    slave_t *s = u;
    memset(s->slot, 0xFF, size);
    return 0;
}

static int flash_write(void *u, size_t off, const uint8_t *d, size_t n)
{
    slave_t *s = u;
    memcpy(&s->slot[off], d, n);
    return 0;
}

static int flash_read(void *u, size_t off, uint8_t *d, size_t n)
{
    slave_t *s = u;
    memcpy(d, &s->slot[off], n);
    return 0;
}

/* DEMO ONLY: stands in for the vendor signature + anti-rollback check. */
static int demo_verify_signature(void *u, size_t size)
{
    slave_t *s = u;
    if (size < TRAILER_SIZE)
        return -1;
    const uint8_t *t = &s->slot[size - TRAILER_SIZE];
    if (memcmp(t, "DSIG", 4) != 0)
        return -1;
    uint32_t version = t[4] | (t[5] << 8) | (t[6] << 16) | ((uint32_t)t[7] << 24);
    if (version <= s->installed_version)
        return -1;   /* rollback */
    return 0;
}

static int flash_activate(void *u, size_t size)
{
    slave_t *s = u;
    const uint8_t *t = &s->slot[size - TRAILER_SIZE];
    s->installed_version = t[4] | (t[5] << 8) | (t[6] << 16) | ((uint32_t)t[7] << 24);
    return 0;
}

static void slave_init(slave_t *s, uint8_t addr, int drop_percent)
{
    memset(s, 0, sizeof(*s));
    s->addr = addr;
    s->installed_version = 1;
    s->drop_percent = drop_percent;
    s->ops = (uart_dfu_ops_t){
        .user = s, .slot_size = SLOT_SIZE,
        .erase = flash_erase, .write = flash_write, .read = flash_read,
        .verify_signature = demo_verify_signature, .activate = flash_activate,
    };
    uart_dfu_slave_init(&s->dfu, &s->ops);
}

/* Slave receive path: every slave sees every frame on the bus. */
static uart_status_t slave_rx(slave_t *s, const uint8_t *f, size_t n,
                              uint8_t *resp, size_t *resp_len)
{
    switch (uart_frame_type(f, n)) {
    case UART_TYPE_DFU_CHUNK:
        *resp_len = 0;
        return uart_dfu_slave_handle_chunk(&s->dfu, f, n);

    case UART_TYPE_REQUEST: {
        uint8_t req[UART_MAX_PAYLOAD];
        size_t req_len = sizeof(req);
        uint32_t seq;

        uart_status_t st = uart_decode_request(system_key, s->addr, f, n,
                                               req, &req_len, &seq);
        if (st != UART_OK)
            return st;
        if (seq <= s->last_seq)
            return UART_ERR_FORMAT;          /* replay: no response */
        s->last_seq = seq;

        if (!uart_dfu_is_command(req, req_len))
            return UART_ERR_FORMAT;          /* app commands go here */

        uint8_t out[UART_MAX_PAYLOAD];
        size_t out_len = sizeof(out);
        st = uart_dfu_slave_handle_command(&s->dfu, req, req_len,
                                           out, &out_len);
        if (st != UART_OK)
            return st;
        return uart_encode_response(system_key, s->addr, out, out_len,
                                    seq, resp, resp_len);
    }

    default:
        return UART_ERR_FORMAT;
    }
}

/* ---- Bus + master ---------------------------------------------------- */

static uint32_t master_seq[N_SLAVES];   /* battery-backed RAM on the master */
static size_t bus_bytes;
static unsigned bus_frames;

/* Broadcast a frame; each slave may lose it. */
static void bus_broadcast(const uint8_t *f, size_t n)
{
    bus_bytes += n;
    bus_frames++;
    for (int i = 0; i < N_SLAVES; i++) {
        if ((int)(rng() % 100) < slaves[i].drop_percent)
            continue;
        uint8_t junk[UART_RESPONSE_MAX_SIZE];
        size_t junk_len = sizeof(junk);
        slave_rx(&slaves[i], f, n, junk, &junk_len);
    }
}

/* Unicast request/response (modelled as reliable). */
static uart_status_t transact(int i, const uint8_t *req, size_t req_len,
                              uint8_t *resp, size_t *resp_len)
{
    slave_t *s = &slaves[i];
    uint32_t seq = ++master_seq[i];

    uint8_t tx[UART_REQUEST_MAX_SIZE];
    size_t tx_len = sizeof(tx);
    uart_status_t st = uart_encode_request(system_key, s->addr, req, req_len,
                                           seq, tx, &tx_len);
    if (st != UART_OK)
        return st;

    /* Every slave hears the request; only the addressee answers. */
    uint8_t rx[UART_RESPONSE_MAX_SIZE];
    size_t rx_len = 0;
    for (int j = 0; j < N_SLAVES; j++) {
        uint8_t r[UART_RESPONSE_MAX_SIZE];
        size_t r_len = sizeof(r);
        if (slave_rx(&slaves[j], tx, tx_len, r, &r_len) == UART_OK && r_len) {
            memcpy(rx, r, r_len);
            rx_len = r_len;
        }
    }
    bus_bytes += tx_len + rx_len;
    bus_frames += 1 + (rx_len != 0);

    if (rx_len == 0)
        return UART_ERR_FORMAT;

    return uart_decode_response(system_key, s->addr, rx, rx_len, seq,
                                resp, resp_len);
}

static uart_dfu_result_t simple_cmd(int i, uint8_t cmd)
{
    uint8_t resp[UART_MAX_PAYLOAD];
    size_t resp_len = sizeof(resp);
    if (transact(i, &cmd, 1, resp, &resp_len) != UART_OK || resp_len < 1)
        return UART_DFU_RES_BAD_REQUEST;
    return (uart_dfu_result_t)resp[0];
}

typedef struct {
    const uint8_t *file;
    size_t size;
    uint32_t update_id;
    uint8_t image_key[UART_KEY_SIZE];
    uint8_t hash[UART_DFU_HASH_SIZE];
    uint16_t n_chunks;
} update_t;

static void update_prepare(update_t *u, const uint8_t *file, size_t size,
                           uint32_t update_id)
{
    u->file = file;
    u->size = size;
    u->update_id = update_id;
    /* Real master: use a cryptographic RNG for the image key. */
    for (size_t i = 0; i < UART_KEY_SIZE; i++)
        u->image_key[i] = (uint8_t)rng();
    mbedtls_sha256(file, size, u->hash, 0);
    u->n_chunks = uart_dfu_chunk_count((uint32_t)size, UART_DFU_CHUNK_SIZE);
}

static uart_dfu_result_t begin(const update_t *u, int i)
{
    uint8_t req[UART_DFU_BEGIN_SIZE];
    size_t req_len = sizeof(req);
    uart_dfu_build_begin(u->update_id, (uint32_t)u->size, UART_DFU_CHUNK_SIZE,
                         u->hash, u->image_key, req, &req_len);

    uint8_t resp[UART_MAX_PAYLOAD];
    size_t resp_len = sizeof(resp);
    if (transact(i, req, req_len, resp, &resp_len) != UART_OK)
        return UART_DFU_RES_BAD_REQUEST;
    return (uart_dfu_result_t)resp[0];
}

static void broadcast_chunk(const update_t *u, uint16_t idx)
{
    size_t off = (size_t)idx * UART_DFU_CHUNK_SIZE;
    size_t len = u->size - off;
    if (len > UART_DFU_CHUNK_SIZE)
        len = UART_DFU_CHUNK_SIZE;

    uint8_t f[UART_CHUNK_MAX_SIZE];
    size_t f_len = sizeof(f);
    uart_encode_dfu_chunk(u->image_key, u->update_id, idx,
                          &u->file[off], len, f, &f_len);
    bus_broadcast(f, f_len);
}

/* Broadcast all chunks, then re-broadcast missing ones until complete. */
static int transfer(const update_t *u)
{
    uint8_t need[UART_DFU_BITMAP_MAX];
    memset(need, 0xFF, sizeof(need));

    for (int round = 1; round <= 10; round++) {
        unsigned sent = 0;
        for (uint16_t c = 0; c < u->n_chunks; c++)
            if (uart_dfu_bit(need, c)) {
                broadcast_chunk(u, c);
                sent++;
            }

        memset(need, 0, sizeof(need));
        unsigned missing_total = 0;

        for (int i = 0; i < N_SLAVES; i++) {
            uint8_t cmd = UART_DFU_CMD_STATUS;
            uint8_t resp[UART_MAX_PAYLOAD];
            size_t resp_len = sizeof(resp);
            uart_dfu_status_t st;

            if (transact(i, &cmd, 1, resp, &resp_len) != UART_OK ||
                uart_dfu_parse_status(resp, resp_len, &st) != UART_OK)
                return -1;

            if (st.state != UART_DFU_RECEIVING || st.update_id != u->update_id)
                continue;   /* not taking part (or already failed) */

            for (size_t b = 0; b < st.bitmap_len; b++)
                need[b] |= st.bitmap[b];
            missing_total += st.missing;
        }

        printf("  round %d: broadcast %u chunks, %u still missing\n",
               round, sent, missing_total);
        if (missing_total == 0)
            return 0;
    }
    return -1;
}

/* ---- Tests ----------------------------------------------------------- */

static int failures;

static void expect_res(const char *what, uart_dfu_result_t got,
                       uart_dfu_result_t want)
{
    int ok = (got == want);
    printf("  [%s] %-46s result=%d\n", ok ? "PASS" : "FAIL", what, got);
    if (!ok)
        failures++;
}

static void expect_st(const char *what, uart_status_t got, uart_status_t want)
{
    int ok = (got == want);
    printf("  [%s] %-46s status=%d\n", ok ? "PASS" : "FAIL", what, got);
    if (!ok)
        failures++;
}

static uint8_t file_a[40 * 1024];
static uint8_t file_b[40 * 1024];
static uint8_t file_c[8 * 1024];

int main(void)
{
    slave_init(&slaves[0], 0x01, 5);
    slave_init(&slaves[1], 0x02, 15);
    slave_init(&slaves[2], 0x03, 30);

    /* ---- 1. Normal update, lossy bus ---- */
    printf("Update v2 (lossy bus: 5%%/15%%/30%% frame loss):\n");

    size_t size_a = make_dfu_file(file_a, 30000, 2, 1);
    update_t ua;
    update_prepare(&ua, file_a, size_a, 1001);

    bus_bytes = 0;
    bus_frames = 0;

    for (int i = 0; i < N_SLAVES; i++)
        expect_res("BEGIN", begin(&ua, i), UART_DFU_RES_OK);

    expect_res("ACTIVATE before FINISH refused",
               simple_cmd(0, UART_DFU_CMD_ACTIVATE), UART_DFU_RES_BAD_STATE);

    if (transfer(&ua) != 0) {
        printf("  [FAIL] transfer did not complete\n");
        failures++;
    }

    for (int i = 0; i < N_SLAVES; i++)
        expect_res("FINISH (hash + signature)",
                   simple_cmd(i, UART_DFU_CMD_FINISH), UART_DFU_RES_OK);
    for (int i = 0; i < N_SLAVES; i++)
        expect_res("ACTIVATE", simple_cmd(i, UART_DFU_CMD_ACTIVATE),
                   UART_DFU_RES_OK);

    printf("  %zu-byte DFU file, %u chunks: %u frames, %zu bytes on the bus\n"
           "  -> about %.0f s at %d baud (8N1)\n",
           size_a, ua.n_chunks, bus_frames, bus_bytes,
           bus_bytes * 10.0 / BAUD, BAUD);

    for (int i = 0; i < N_SLAVES; i++)
        if (slaves[i].installed_version != 2) {
            printf("  [FAIL] slave %d not on v2\n", i);
            failures++;
        }

    /* ---- 2. Attacks during update v3 ---- */
    printf("\nUpdate v3 with attacks:\n");

    size_t size_b = make_dfu_file(file_b, 20000, 3, 1);
    update_t ub;
    update_prepare(&ub, file_b, size_b, 1002);

    for (int i = 0; i < N_SLAVES; i++) {
        slaves[i].drop_percent = 0;
        begin(&ub, i);
    }

    uint8_t f[UART_CHUNK_MAX_SIZE];
    size_t f_len;
    uint8_t garbage[UART_DFU_CHUNK_SIZE];
    memset(garbage, 0xEE, sizeof(garbage));

    /* Outsider: does not know the image key. */
    uint8_t wrong_key[UART_KEY_SIZE] = { 0 };
    f_len = sizeof(f);
    uart_encode_dfu_chunk(wrong_key, ub.update_id, 0, garbage,
                          UART_DFU_CHUNK_SIZE, f, &f_len);
    expect_st("outsider chunk rejected",
              uart_dfu_slave_handle_chunk(&slaves[0].dfu, f, f_len),
              UART_ERR_AUTH);

    /* Chunk recorded from the previous update. */
    f_len = sizeof(f);
    uart_encode_dfu_chunk(ua.image_key, ua.update_id, 0, file_a,
                          UART_DFU_CHUNK_SIZE, f, &f_len);
    expect_st("chunk from previous update rejected",
              uart_dfu_slave_handle_chunk(&slaves[0].dfu, f, f_len),
              UART_ERR_AUTH);

    /* Compromised slave 3 knows the image key: forges chunk 5 to slave 2
     * before the real one arrives. */
    f_len = sizeof(f);
    uart_encode_dfu_chunk(ub.image_key, ub.update_id, 5, garbage,
                          UART_DFU_CHUNK_SIZE, f, &f_len);
    expect_st("insider-forged chunk passes transport check",
              uart_dfu_slave_handle_chunk(&slaves[1].dfu, f, f_len),
              UART_OK);

    transfer(&ub);

    expect_res("slave 1: FINISH", simple_cmd(0, UART_DFU_CMD_FINISH),
               UART_DFU_RES_OK);
    expect_res("slave 2: forged image caught by hash",
               simple_cmd(1, UART_DFU_CMD_FINISH),
               UART_DFU_RES_HASH_MISMATCH);
    expect_res("slave 2: ACTIVATE refused after failure",
               simple_cmd(1, UART_DFU_CMD_ACTIVATE), UART_DFU_RES_BAD_STATE);

    /* Recovery: BEGIN again restarts the failed slave; others keep state. */
    expect_res("slave 2: BEGIN again", begin(&ub, 1), UART_DFU_RES_OK);
    transfer(&ub);
    expect_res("slave 2: FINISH after retry",
               simple_cmd(1, UART_DFU_CMD_FINISH), UART_DFU_RES_OK);
    expect_res("slave 3: FINISH", simple_cmd(2, UART_DFU_CMD_FINISH),
               UART_DFU_RES_OK);

    /* ---- 3. Bad images pushed by a compromised master ---- */
    printf("\nImages a compromised master might push:\n");

    size_t size_c = make_dfu_file(file_c, 4000, 9, 0);   /* unsigned */
    update_t uc;
    update_prepare(&uc, file_c, size_c, 1003);
    begin(&uc, 0);
    transfer(&uc);
    expect_res("unsigned image rejected",
               simple_cmd(0, UART_DFU_CMD_FINISH),
               UART_DFU_RES_SIGNATURE_INVALID);

    size_c = make_dfu_file(file_c, 4000, 1, 1);   /* signed, but old v1 */
    update_prepare(&uc, file_c, size_c, 1004);
    begin(&uc, 0);
    transfer(&uc);
    expect_res("rollback to v1 rejected",
               simple_cmd(0, UART_DFU_CMD_FINISH),
               UART_DFU_RES_SIGNATURE_INVALID);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
