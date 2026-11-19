#ifndef UART_SIMPLE_H
#define UART_SIMPLE_H

/*
 * Read-modify-write polling with deferred status authentication.
 *
 *   M -> S  READ                      plaintext, CRC-16
 *   S -> M  STATUS | s                plaintext, CRC-16; slave keeps snapshot s
 *   M -> S  CMD    | c   | TAG        AES-CCM, AAD includes s' (master's copy)
 *   S -> M  ACK    | r   | TAG        AES-CCM, AAD includes s and c
 *
 * READ/STATUS carry no cryptographic overhead. The status is authenticated
 * when the slave verifies the CMD tag against the snapshot it actually sent:
 * a forged/replayed/corrupted STATUS makes the CMD fail, so no command is
 * ever executed on a status the slave did not report.
 *
 * The master must treat the status as PROVISIONAL until a valid ACK, and
 * only then fold it into its global state.
 *
 * Frame:  SOF | ADDR | CTRL | BODY | CRC-16 or TAG
 *         CTRL = TYPE (bits 7..6) | LEN (bits 5..0), LEN = body length
 *
 * ---------------------------------------------------------------------------
 * EPOCH + SEQ (nonce management)
 *
 * Nonce = TYPE | ADDR | EPOCH (4, LE) | SEQ (4, LE) | 0 0 0   (13 bytes)
 * Neither EPOCH nor SEQ is transmitted in CMD/ACK frames.
 *
 * EPOCH is a hardware monotonic counter on the master (ATECC608). SEQ is a
 * per-slave counter in battery-backed RAM. On master boot, if the BBRAM is
 * invalid (VBAT loss, tamper erase, crash mid-update) the master increments
 * the monotonic counter BEFORE sending anything and restarts all SEQs at 0.
 * (EPOCH, SEQ) therefore never repeats, whatever happens to the BBRAM.
 *
 * The slave keeps EPOCH in flash and SEQ in RAM. It accepts a CMD under:
 *     (E,   last_seq+1 .. last_seq+W)   if its SEQ state is valid
 *     (E+k, 1 .. W)                     k = 1..UART_SIMPLE_EPOCH_LOOKAHEAD
 * Moving to a new epoch persists it to flash BEFORE the command executes.
 *
 * After a slave reboot its SEQ state is lost, so it refuses its stored
 * epoch entirely; the master must bump the epoch (all slaves follow
 * automatically). This replaces any SYNC exchange.
 *
 * A slave more than LOOKAHEAD epochs behind needs an ANNOUNCE: a READ with
 * body EPOCH | SEQ, authenticated with a tag. It is accepted only if EPOCH
 * is greater than the slave's stored epoch, and is answered with STATUS.
 * ---------------------------------------------------------------------------
 *
 *   CMD AAD      = ADDR | CTRL | len(s) | s
 *   ACK AAD      = ADDR | CTRL | len(s) | s | len(c) | c
 *   ANNOUNCE AAD = ADDR | CTRL | EPOCH | SEQ   (no ciphertext, tag only)
 *
 * Status is NOT confidential (plaintext on the bus). Commands and ACK
 * results are encrypted.
 */

#include <stdint.h>
#include <stddef.h>

#define UART_SIMPLE_SOF             0x7E
#define UART_SIMPLE_KEY_SIZE        16
#define UART_SIMPLE_TAG_SIZE        4     /* CCM: 4, 6, 8, ..., 16 */
#define UART_SIMPLE_CRC_SIZE        2
#define UART_SIMPLE_MAX_BODY        63    /* 6-bit LEN */
#define UART_SIMPLE_SEQ_WINDOW      8     /* tolerated lost CMD frames */
#define UART_SIMPLE_EPOCH_LOOKAHEAD 2     /* epochs a slave follows silently */
#define UART_SIMPLE_ANNOUNCE_BODY   8     /* EPOCH (4) | SEQ (4) */

#define UART_SIMPLE_HDR_SIZE        3     /* SOF, ADDR, CTRL */
#define UART_SIMPLE_MAX_FRAME       (UART_SIMPLE_HDR_SIZE + UART_SIMPLE_MAX_BODY + \
                                     UART_SIMPLE_TAG_SIZE + UART_SIMPLE_CRC_SIZE)

typedef enum {
    UART_SIMPLE_TYPE_READ   = 0,   /* body empty: READ; body 8: ANNOUNCE */
    UART_SIMPLE_TYPE_STATUS = 1,
    UART_SIMPLE_TYPE_CMD    = 2,
    UART_SIMPLE_TYPE_ACK    = 3
} uart_simple_type_t;

/* ACK result (encrypted inside the ACK) */
typedef enum {
    UART_SIMPLE_RES_EXECUTED = 0,
    UART_SIMPLE_RES_STALE    = 1,  /* status changed since READ: not executed */
    UART_SIMPLE_RES_REJECTED = 2   /* application refused the command */
} uart_simple_result_t;

typedef enum {
    UART_SIMPLE_OK = 0,
    UART_SIMPLE_ERR_ARGUMENT,
    UART_SIMPLE_ERR_LENGTH,
    UART_SIMPLE_ERR_BUFFER,
    UART_SIMPLE_ERR_FORMAT,
    UART_SIMPLE_ERR_ADDR,     /* not for us: ignore silently */
    UART_SIMPLE_ERR_CRC,
    UART_SIMPLE_ERR_AUTH,
    UART_SIMPLE_ERR_STATE,    /* step out of order (e.g. CMD without READ) */
    UART_SIMPLE_ERR_STALE,    /* CMD authentic but status changed: send ACK */
    UART_SIMPLE_ERR_SEQ,      /* SEQ exhausted: call uart_simple_epoch_bump() */
    UART_SIMPLE_ERR_EPOCH,    /* monotonic counter failure / exhausted */
    UART_SIMPLE_ERR_PERSIST,  /* slave could not store the new epoch */
    UART_SIMPLE_ERR_CRYPTO
} uart_simple_status_t;

/* Quick dispatch helpers (no checks beyond the header). */
int uart_simple_frame_type(const uint8_t *frame, size_t len);   /* -1 if bad */
int uart_simple_frame_addr(const uint8_t *frame, size_t len);   /* -1 if bad */

/* ---- Master: epoch + persistent SEQ table ---------------------------- */

/* Hardware monotonic counter (e.g. ATECC608 Counter command). */
typedef struct {
    void *user;
    int (*read)(void *user, uint32_t *value);            /* 0 = ok */
    int (*increment)(void *user, uint32_t *new_value);   /* 0 = ok */
} uart_simple_counter_ops_t;

/* Layout of the battery-backed RAM area. */
typedef struct {
    uint32_t magic;
    uint32_t epoch;
    uint32_t n_slaves;
    uint32_t check;
    uint32_t seq[];          /* last used SEQ, one per slave slot */
} uart_simple_bbram_t;

#define UART_SIMPLE_BBRAM_SIZE(n) (sizeof(uart_simple_bbram_t) + (n) * sizeof(uint32_t))

typedef struct {
    const uart_simple_counter_ops_t *ops;
    uart_simple_bbram_t *bb;
    uint32_t epoch;
} uart_simple_epoch_t;

/*
 * Call once at master boot, before any frame is sent. Validates the BBRAM
 * against the monotonic counter; if anything is off, bumps the epoch and
 * clears all SEQs. *bumped (optional) reports whether that happened.
 */
uart_simple_status_t uart_simple_epoch_boot(
    uart_simple_epoch_t *e, const uart_simple_counter_ops_t *ops,
    uart_simple_bbram_t *bb, uint32_t n_slaves, int *bumped);

/*
 * Start a new epoch: all slaves restart at SEQ 1 and follow automatically.
 * Use when a slave has rebooted (it refuses the current epoch) or a SEQ is
 * exhausted. RATE-LIMIT THIS in the application: it consumes the hardware
 * counter, and an attacker who can suppress ACKs could otherwise burn it.
 */
uart_simple_status_t uart_simple_epoch_bump(uart_simple_epoch_t *e);

/* ---- Master: one context per slave ----------------------------------- */

typedef struct {
    const uint8_t *key;
    uint8_t  addr;
    uart_simple_epoch_t *ep;
    uint32_t slot;           /* index into ep->bb->seq[] */

    /* Provisional status from the last STATUS frame */
    uint8_t  status[UART_SIMPLE_MAX_BODY];
    uint8_t  status_len;
    uint8_t  status_valid;

    /* Outstanding command, needed to verify the ACK */
    uint8_t  cmd[UART_SIMPLE_MAX_BODY];
    uint8_t  cmd_len;
    uint32_t cmd_epoch;
    uint32_t cmd_seq;
    uint8_t  cmd_pending;
} uart_simple_master_t;

void uart_simple_master_init(uart_simple_master_t *m, const uint8_t *key,
                             uint8_t addr, uart_simple_epoch_t *ep,
                             uint32_t slot);

/* Build a READ frame. Clears any previous provisional status. */
uart_simple_status_t uart_simple_master_build_read(
    uart_simple_master_t *m, uint8_t *dst, size_t *dst_len);

/*
 * Build an ANNOUNCE (READ carrying the current EPOCH and a fresh SEQ) for a
 * slave that is more than UART_SIMPLE_EPOCH_LOOKAHEAD epochs behind. The
 * slave answers with STATUS, so it replaces the READ of that cycle.
 * It does not help a slave that rebooted in the current epoch: bump instead.
 */
uart_simple_status_t uart_simple_master_build_announce(
    uart_simple_master_t *m, uint8_t *dst, size_t *dst_len);

/*
 * Accept a STATUS frame. On success the status is available in m->status
 * as PROVISIONAL: use it to compute this slave's command, but do not fold it
 * into shared master state before uart_simple_master_handle_ack() succeeds.
 */
uart_simple_status_t uart_simple_master_handle_status(
    uart_simple_master_t *m, const uint8_t *frame, size_t len);

/* Build a CMD bound to the provisional status. Consumes one SEQ. */
uart_simple_status_t uart_simple_master_build_cmd(
    uart_simple_master_t *m, const uint8_t *cmd, size_t cmd_len,
    uint8_t *dst, size_t *dst_len);

/*
 * Verify the ACK. On UART_SIMPLE_OK, *result says what the slave did, and
 * m->status is CONFIRMED as the status the slave reported.
 */
uart_simple_status_t uart_simple_master_handle_ack(
    uart_simple_master_t *m, const uint8_t *frame, size_t len,
    uart_simple_result_t *result);

/* ---- Slave ----------------------------------------------------------- */

/* Store the epoch in non-volatile memory. Must be durable on return. */
typedef int (*uart_simple_persist_fn)(void *user, uint32_t epoch);

typedef struct {
    const uint8_t *key;
    uint8_t  addr;

    uint32_t epoch;          /* mirrors the value in flash */
    uint32_t last_seq;
    uint8_t  seq_valid;      /* 0 after reboot: stored epoch is refused */

    uart_simple_persist_fn persist;
    void *persist_user;

    /* Status snapshot sent in the last STATUS frame */
    uint8_t  snap[UART_SIMPLE_MAX_BODY];
    uint8_t  snap_len;
    uint8_t  snap_valid;

    /* Accepted command awaiting its ACK (with the snapshot it was bound to,
     * so a READ arriving in between cannot change the ACK's AAD) */
    uint8_t  cmd[UART_SIMPLE_MAX_BODY];
    uint8_t  cmd_len;
    uint8_t  ack_snap[UART_SIMPLE_MAX_BODY];
    uint8_t  ack_snap_len;
    uint32_t cmd_epoch;
    uint32_t cmd_seq;
    uint8_t  ack_pending;
} uart_simple_slave_t;

/*
 * stored_epoch: the epoch read from flash.
 * fresh_key:    1 right after commissioning with a new key (the master
 *               starts this slave at SEQ 1 in stored_epoch); 0 after any
 *               reboot (stored_epoch is refused until the master bumps).
 */
void uart_simple_slave_init(uart_simple_slave_t *s, const uint8_t *key,
                            uint8_t addr, uint32_t stored_epoch,
                            int fresh_key,
                            uart_simple_persist_fn persist, void *persist_user);

/*
 * Handle a READ (or ANNOUNCE) addressed to us: build STATUS and remember
 * the snapshot.
 */
uart_simple_status_t uart_simple_slave_handle_read(
    uart_simple_slave_t *s, const uint8_t *frame, size_t len,
    const uint8_t *status, size_t status_len,
    uint8_t *dst, size_t *dst_len);

/*
 * Handle a CMD addressed to us.
 *   UART_SIMPLE_OK     authentic and status unchanged: execute cmd_out,
 *                      then call uart_simple_slave_build_ack().
 *   UART_SIMPLE_ERR_STALE  authentic but status changed: do NOT execute,
 *                      call uart_simple_slave_build_ack(.., RES_STALE ..).
 *   anything else      drop silently, send nothing.
 * current_status is the slave's status right now (for the atomic check).
 */
uart_simple_status_t uart_simple_slave_handle_cmd(
    uart_simple_slave_t *s, const uint8_t *frame, size_t len,
    const uint8_t *current_status, size_t current_status_len,
    uint8_t *cmd_out, size_t *cmd_out_len);

/* Build the ACK for the command just handled (exactly once per command). */
uart_simple_status_t uart_simple_slave_build_ack(
    uart_simple_slave_t *s, uart_simple_result_t result,
    uint8_t *dst, size_t *dst_len);

#endif
