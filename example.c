#include "uart_frame.h"

#include <stdio.h>
#include <string.h>

static const uint8_t system_key[16] = {
    0xA3, 0x7F, 0x19, 0xC2,
    0xE8, 0x4B, 0x60, 0x5D,
    0x91, 0xF0, 0x3A, 0x7C,
    0x52, 0xD8, 0xB6, 0x41
};

#define SLAVE_ADDR 0x05

static void dump(const char *label, const uint8_t *p, size_t n)
{
    printf("%-9s (%3zu B):", label, n);
    for (size_t i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

/* ---- Simulated slave ------------------------------------------------- */

static uint32_t slave_last_seq;   /* RAM only: lost on reboot (needs SYNC) */

/*
 * Handle one received frame. Returns UART_OK and fills resp/resp_len if a
 * response should be sent; any other status means "send nothing".
 */
static uart_status_t slave_handle(const uint8_t *frame, size_t frame_len,
                                  uint8_t *resp, size_t *resp_len)
{
    uint8_t req[UART_MAX_PAYLOAD];
    size_t req_len = sizeof(req);
    uint32_t seq;

    uart_status_t st = uart_decode_request(system_key, SLAVE_ADDR,
                                           frame, frame_len,
                                           req, &req_len, &seq);
    if (st != UART_OK)
        return st;

    /* Replay protection. Also guarantees at most one response per SEQ,
     * which keeps response nonces unique. */
    if (seq <= slave_last_seq)
        return UART_ERR_FORMAT;
    slave_last_seq = seq;

    /* Application: echo the request back, bit-inverted. */
    uint8_t out[UART_MAX_PAYLOAD];
    for (size_t i = 0; i < req_len; i++)
        out[i] = (uint8_t)~req[i];

    return uart_encode_response(system_key, SLAVE_ADDR, out, req_len,
                                seq, resp, resp_len);
}

/* ---- Test helpers ---------------------------------------------------- */

static int failures;

static void expect(const char *what, uart_status_t got, uart_status_t want)
{
    int ok = (got == want);
    printf("  [%s] %-40s status=%d\n", ok ? "PASS" : "FAIL", what, got);
    if (!ok)
        failures++;
}

int main(void)
{
    uint8_t tx[UART_REQUEST_MAX_SIZE];
    uint8_t rx[UART_RESPONSE_MAX_SIZE];

    uint8_t request[] = { 0x12, 0x34 };
    uint8_t response[32];

    uint32_t seq = 1234;   /* master: would live in battery-backed RAM */

    /* Master: build request */
    size_t tx_len = sizeof(tx);
    uart_status_t st = uart_encode_request(system_key, SLAVE_ADDR,
                                           request, sizeof(request),
                                           seq, tx, &tx_len);
    expect("encode request", st, UART_OK);
    dump("request", tx, tx_len);

    /* Send request ... slave receives it */
    size_t rx_len = sizeof(rx);
    st = slave_handle(tx, tx_len, rx, &rx_len);
    expect("slave accepts request", st, UART_OK);
    dump("response", rx, rx_len);

    /* Receive response */
    size_t response_len = sizeof(response);
    st = uart_decode_response(system_key, SLAVE_ADDR, rx, rx_len,
                              seq, response, &response_len);
    expect("master accepts response", st, UART_OK);

    if (response_len != sizeof(request) ||
        response[0] != (uint8_t)~request[0] ||
        response[1] != (uint8_t)~request[1]) {
        printf("  [FAIL] response payload mismatch\n");
        failures++;
    }

    printf("\nAttacks:\n");

    /* Replay of the same request */
    size_t junk_len = sizeof(rx);
    uint8_t junk[UART_RESPONSE_MAX_SIZE];
    st = slave_handle(tx, tx_len, junk, &junk_len);
    expect("replayed request rejected", st, UART_ERR_FORMAT);

    /* Frame for another slave */
    uint8_t other[UART_REQUEST_MAX_SIZE];
    size_t other_len = sizeof(other);
    uart_encode_request(system_key, 0x06, request, sizeof(request),
                        seq + 1, other, &other_len);
    junk_len = sizeof(junk);
    st = slave_handle(other, other_len, junk, &junk_len);
    expect("frame for other slave ignored", st, UART_ERR_ADDR);

    /* Redirect: rewrite ADDR of slave 6's frame to 5 */
    other[1] = SLAVE_ADDR;
    junk_len = sizeof(junk);
    st = slave_handle(other, other_len, junk, &junk_len);
    expect("redirected frame rejected", st, UART_ERR_AUTH);

    /* Ciphertext bit flip */
    uint8_t bad[UART_REQUEST_MAX_SIZE];
    size_t bad_len = sizeof(bad);
    uart_encode_request(system_key, SLAVE_ADDR, request, sizeof(request),
                        seq + 2, bad, &bad_len);
    bad[UART_HEADER_SIZE + UART_SEQ_SIZE] ^= 0x01;
    junk_len = sizeof(junk);
    st = slave_handle(bad, bad_len, junk, &junk_len);
    expect("tampered ciphertext rejected", st, UART_ERR_AUTH);

    /* SEQ changed on the wire */
    bad_len = sizeof(bad);
    uart_encode_request(system_key, SLAVE_ADDR, request, sizeof(request),
                        seq + 3, bad, &bad_len);
    bad[4] ^= 0x01;
    junk_len = sizeof(junk);
    st = slave_handle(bad, bad_len, junk, &junk_len);
    expect("tampered SEQ rejected", st, UART_ERR_AUTH);

    /* Old response replayed against a newer request */
    response_len = sizeof(response);
    st = uart_decode_response(system_key, SLAVE_ADDR, rx, rx_len,
                              seq + 10, response, &response_len);
    expect("stale response rejected", st, UART_ERR_AUTH);

    /* Request reflected back to the master as a response */
    uint8_t refl[UART_RESPONSE_MAX_SIZE];
    refl[0] = UART_SOF;
    refl[1] = SLAVE_ADDR;
    refl[2] = UART_TYPE_RESPONSE;
    refl[3] = tx[3];
    memcpy(&refl[4], &tx[UART_HEADER_SIZE + UART_SEQ_SIZE],
           tx[3] + UART_TAG_SIZE);
    response_len = sizeof(response);
    st = uart_decode_response(system_key, SLAVE_ADDR, refl,
                              UART_RESPONSE_OVERHEAD + tx[3],
                              seq, response, &response_len);
    expect("reflected request rejected", st, UART_ERR_AUTH);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
