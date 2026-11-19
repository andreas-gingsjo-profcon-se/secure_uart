/*
 * uart_simple: RMW cycles, attacks, and epoch recovery
 * (VBAT loss, crash during bump, slave reboot, slave far behind).
 */
#include "uart_simple.h"

#include <stdio.h>
#include <string.h>

static const uint8_t key[16] = {
    0xA3, 0x7F, 0x19, 0xC2, 0xE8, 0x4B, 0x60, 0x5D,
    0x91, 0xF0, 0x3A, 0x7C, 0x52, 0xD8, 0xB6, 0x41
};

#define ADDR     0x2A
#define N_SLAVES 4

static int failures;

static void expect(const char *what, long got, long want)
{
    int ok = (got == want);
    printf("  [%s] %-52s got=%ld\n", ok ? "PASS" : "FAIL", what, got);
    if (!ok)
        failures++;
}

static void dump(const char *label, const uint8_t *p, size_t n)
{
    printf("    %-8s (%2zu B):", label, n);
    for (size_t i = 0; i < n; i++)
        printf(" %02x", p[i]);
    printf("\n");
}

/* ---- Master hardware: ATECC608 counter + backup SRAM ----------------- */

static uint32_t atecc_counter = 5;

static int ctr_read(void *u, uint32_t *v)
{
    (void)u;
    *v = atecc_counter;
    return 0;
}

static int ctr_inc(void *u, uint32_t *v)
{
    (void)u;
    *v = ++atecc_counter;
    return 0;
}

static const uart_simple_counter_ops_t ctr_ops = { NULL, ctr_read, ctr_inc };

static union {
    uart_simple_bbram_t bb;
    uint8_t raw[UART_SIMPLE_BBRAM_SIZE(N_SLAVES)];
} bbram;                                    /* "battery-backed" */

static uart_simple_epoch_t   EP;
static uart_simple_master_t  M;

static void master_boot(int *bumped)
{
    uart_simple_status_t st = uart_simple_epoch_boot(&EP, &ctr_ops, &bbram.bb,
                                                     N_SLAVES, bumped);
    if (st != UART_SIMPLE_OK) {
        printf("  [FAIL] master boot: %d\n", st);
        failures++;
    }
    uart_simple_master_init(&M, key, ADDR, &EP, 0);
}

/* Track every CMD nonce the master ever uses. */
static struct { uint32_t epoch, seq; } used[256];
static int n_used;
static int nonce_reuse;

static void record_nonce(void)
{
    for (int i = 0; i < n_used; i++)
        if (used[i].epoch == M.cmd_epoch && used[i].seq == M.cmd_seq)
            nonce_reuse++;
    if (n_used < 256) {
        used[n_used].epoch = M.cmd_epoch;
        used[n_used].seq = M.cmd_seq;
        n_used++;
    }
}

/* ---- Slave: flash epoch + application state -------------------------- */

static uint32_t slave_flash_epoch;
static int      slave_flash_fail;
static uint8_t  slave_status[4] = { 0x01, 0x00, 0x10, 0x20 };
static uint8_t  slave_output;
static uart_simple_slave_t S;

static int persist(void *u, uint32_t epoch)
{
    (void)u;
    if (slave_flash_fail)
        return -1;
    slave_flash_epoch = epoch;
    return 0;
}

static void slave_boot(int fresh_key)
{
    uart_simple_slave_init(&S, key, ADDR, slave_flash_epoch, fresh_key,
                           persist, NULL);
}

/* Slave receive path. Returns response length (0 = no response). */
static size_t slave_rx(const uint8_t *f, size_t n, uint8_t *out, int *last_st)
{
    size_t out_len = UART_SIMPLE_MAX_FRAME;
    *last_st = UART_SIMPLE_ERR_FORMAT;

    switch (uart_simple_frame_type(f, n)) {
    case UART_SIMPLE_TYPE_READ:
        *last_st = uart_simple_slave_handle_read(&S, f, n, slave_status,
                                                 sizeof(slave_status),
                                                 out, &out_len);
        return *last_st == UART_SIMPLE_OK ? out_len : 0;

    case UART_SIMPLE_TYPE_CMD: {
        uint8_t cmd[UART_SIMPLE_MAX_BODY];
        size_t cmd_len = sizeof(cmd);
        int st = uart_simple_slave_handle_cmd(&S, f, n, slave_status,
                                              sizeof(slave_status),
                                              cmd, &cmd_len);
        *last_st = st;
        if (st == UART_SIMPLE_OK) {
            slave_output = cmd[0];                  /* execute */
            uart_simple_slave_build_ack(&S, UART_SIMPLE_RES_EXECUTED,
                                        out, &out_len);
            return out_len;
        }
        if (st == UART_SIMPLE_ERR_STALE) {
            uart_simple_slave_build_ack(&S, UART_SIMPLE_RES_STALE,
                                        out, &out_len);
            return out_len;
        }
        return 0;
    }

    default:
        return 0;
    }
}

/* ---- One RMW cycle --------------------------------------------------- */

static uint8_t last_cmd_frame[UART_SIMPLE_MAX_FRAME];
static size_t  last_cmd_len;

typedef struct {
    int slave_st;     /* slave's handle_cmd result */
    int ack_st;       /* master's handle_ack result (-1: no ACK) */
    int result;
} cycle_t;

static cycle_t rmw(uint8_t command, int use_announce, int verbose)
{
    uint8_t f[UART_SIMPLE_MAX_FRAME], r[UART_SIMPLE_MAX_FRAME];
    size_t f_len = sizeof(f), r_len;
    int sst;
    cycle_t c = { -1, -1, -1 };

    if (use_announce)
        uart_simple_master_build_announce(&M, f, &f_len);
    else
        uart_simple_master_build_read(&M, f, &f_len);
    if (verbose) dump(use_announce ? "ANNOUNCE" : "READ", f, f_len);

    r_len = slave_rx(f, f_len, r, &sst);
    if (r_len == 0) {
        c.slave_st = sst;
        return c;
    }
    if (verbose) dump("STATUS", r, r_len);
    uart_simple_master_handle_status(&M, r, r_len);

    uint8_t cmd[2] = { command, 0x01 };
    f_len = sizeof(f);
    uart_simple_master_build_cmd(&M, cmd, sizeof(cmd), f, &f_len);
    record_nonce();
    memcpy(last_cmd_frame, f, f_len);
    last_cmd_len = f_len;
    if (verbose) dump("CMD", f, f_len);

    r_len = slave_rx(f, f_len, r, &sst);
    c.slave_st = sst;
    if (r_len) {
        if (verbose) dump("ACK", r, r_len);
        uart_simple_result_t res;
        c.ack_st = uart_simple_master_handle_ack(&M, r, r_len, &res);
        c.result = res;
    }
    return c;
}

static int replay_last_cmd_after_read(void)
{
    uint8_t f[UART_SIMPLE_MAX_FRAME], r[UART_SIMPLE_MAX_FRAME];
    size_t f_len = sizeof(f);
    int sst;
    uart_simple_master_build_read(&M, f, &f_len);   /* fresh snapshot */
    slave_rx(f, f_len, r, &sst);
    slave_rx(last_cmd_frame, last_cmd_len, r, &sst);
    return sst;
}

int main(void)
{
    int bumped;
    cycle_t c;
    uint8_t f[UART_SIMPLE_MAX_FRAME], r[UART_SIMPLE_MAX_FRAME];
    size_t f_len, r_len;
    int sst;

    /* ---- First boot + commissioning ---- */
    printf("First boot (BBRAM empty) + commissioning:\n");
    master_boot(&bumped);
    expect("empty BBRAM forces an epoch bump", bumped, 1);
    expect("epoch = counter", EP.epoch, 6);
    slave_flash_epoch = EP.epoch;          /* learnt at commissioning */
    slave_boot(1);

    c = rmw(0x55, 0, 1);
    expect("normal cycle: slave executes", c.slave_st, UART_SIMPLE_OK);
    expect("normal cycle: ACK verified", c.ack_st, UART_SIMPLE_OK);
    expect("slave output", slave_output, 0x55);

    /* ---- Attacks from the base protocol ---- */
    printf("\nAttacks:\n");
    slave_output = 0;
    expect("replayed CMD rejected", replay_last_cmd_after_read(),
           UART_SIMPLE_ERR_AUTH);
    expect("  ... not executed", slave_output, 0);

    f_len = sizeof(f);
    uart_simple_master_build_read(&M, f, &f_len);
    r_len = slave_rx(f, f_len, r, &sst);
    uart_simple_master_handle_status(&M, r, r_len);
    M.status[0] ^= 0x01;                   /* master got a forged status */
    f_len = sizeof(f);
    uint8_t cmd[2] = { 0x66, 0x01 };
    uart_simple_master_build_cmd(&M, cmd, sizeof(cmd), f, &f_len);
    record_nonce();
    r_len = slave_rx(f, f_len, r, &sst);
    expect("CMD based on forged STATUS rejected", sst, UART_SIMPLE_ERR_AUTH);

    slave_status[0] = 0x02;
    f_len = sizeof(f);
    uart_simple_master_build_read(&M, f, &f_len);
    r_len = slave_rx(f, f_len, r, &sst);
    uart_simple_master_handle_status(&M, r, r_len);
    slave_status[0] = 0x03;                /* moves before CMD */
    f_len = sizeof(f);
    uart_simple_master_build_cmd(&M, cmd, sizeof(cmd), f, &f_len);
    record_nonce();
    r_len = slave_rx(f, f_len, r, &sst);
    expect("stale CMD not executed", sst, UART_SIMPLE_ERR_STALE);

    c = rmw(0x11, 0, 0);
    expect("next cycle fine (after lost/rejected SEQs)", c.ack_st, UART_SIMPLE_OK);

    /* ---- Master reboot, BBRAM intact ---- */
    printf("\nMaster reboot, BBRAM intact:\n");
    uint32_t before = EP.epoch;
    master_boot(&bumped);
    expect("no bump", bumped, 0);
    expect("epoch unchanged", EP.epoch, before);
    c = rmw(0x21, 0, 0);
    expect("cycle OK", c.ack_st, UART_SIMPLE_OK);

    /* ---- VBAT loss ---- */
    printf("\nMaster reboot + VBAT loss:\n");
    uint8_t old_cmd[UART_SIMPLE_MAX_FRAME];
    size_t old_cmd_len = last_cmd_len;
    memcpy(old_cmd, last_cmd_frame, last_cmd_len);

    memset(&bbram, 0, sizeof(bbram));
    master_boot(&bumped);
    expect("epoch bumped", bumped, 1);
    expect("new epoch", EP.epoch, 7);
    c = rmw(0x31, 0, 1);
    expect("slave follows to E+1 silently", c.ack_st, UART_SIMPLE_OK);
    expect("slave persisted new epoch", slave_flash_epoch, 7);

    f_len = sizeof(f);
    uart_simple_master_build_read(&M, f, &f_len);
    slave_rx(f, f_len, r, &sst);
    slave_rx(old_cmd, old_cmd_len, r, &sst);
    expect("CMD from previous epoch rejected", sst, UART_SIMPLE_ERR_AUTH);

    /* ---- Crash right after the counter increment ---- */
    printf("\nCrash between counter increment and BBRAM update:\n");
    bbram.bb.magic = 0;                    /* bump started ... */
    atecc_counter++;                       /* ... counter burned, crash */
    master_boot(&bumped);
    expect("bumps again on boot", bumped, 1);
    expect("epoch skipped one", EP.epoch, 9);
    c = rmw(0x41, 0, 0);
    expect("slave follows E+2 silently", c.ack_st, UART_SIMPLE_OK);
    expect("slave flash epoch", slave_flash_epoch, 9);

    /* ---- Slave reboot ---- */
    printf("\nSlave reboot (SEQ state lost):\n");
    uint8_t pre_reboot[UART_SIMPLE_MAX_FRAME];
    size_t pre_reboot_len = last_cmd_len;
    memcpy(pre_reboot, last_cmd_frame, last_cmd_len);

    slave_boot(0);
    c = rmw(0x51, 0, 0);
    expect("current epoch refused after reboot", c.slave_st, UART_SIMPLE_ERR_AUTH);

    f_len = sizeof(f);
    uart_simple_master_build_read(&M, f, &f_len);
    slave_rx(f, f_len, r, &sst);
    slave_rx(pre_reboot, pre_reboot_len, r, &sst);
    expect("pre-reboot CMD cannot be replayed", sst, UART_SIMPLE_ERR_AUTH);

    c = rmw(0x52, 1, 0);
    expect("ANNOUNCE of current epoch refused", c.slave_st, UART_SIMPLE_ERR_AUTH);

    uart_simple_epoch_bump(&EP);
    c = rmw(0x53, 0, 0);
    expect("after master bump: slave follows", c.ack_st, UART_SIMPLE_OK);
    expect("slave output", slave_output, 0x53);

    /* ---- Slave far behind ---- */
    printf("\nSlave more than %d epochs behind:\n", UART_SIMPLE_EPOCH_LOOKAHEAD);
    for (int i = 0; i < 3; i++)
        uart_simple_epoch_bump(&EP);
    c = rmw(0x61, 0, 0);
    expect("plain CMD rejected (out of lookahead)", c.slave_st, UART_SIMPLE_ERR_AUTH);
    c = rmw(0x62, 1, 1);
    expect("ANNOUNCE + CMD accepted", c.ack_st, UART_SIMPLE_OK);
    expect("slave flash epoch", slave_flash_epoch, EP.epoch);

    f_len = sizeof(f);
    uart_simple_master_build_announce(&M, f, &f_len);   /* record one */
    uint8_t ann[UART_SIMPLE_MAX_FRAME];
    size_t ann_len = f_len;
    memcpy(ann, f, f_len);
    slave_rx(f, f_len, r, &sst);
    expect("ANNOUNCE for current epoch refused (no rewind)", sst,
           UART_SIMPLE_ERR_AUTH);
    ann[5] ^= 0x01;                        /* tamper with EPOCH */
    slave_rx(ann, ann_len, r, &sst);
    expect("tampered ANNOUNCE rejected", sst, UART_SIMPLE_ERR_AUTH);

    /* ---- Flash write failure ---- */
    printf("\nSlave cannot persist the new epoch:\n");
    uart_simple_epoch_bump(&EP);
    slave_flash_fail = 1;
    slave_output = 0;
    c = rmw(0x71, 0, 0);
    expect("CMD refused", c.slave_st, UART_SIMPLE_ERR_PERSIST);
    expect("  ... not executed", slave_output, 0);
    slave_flash_fail = 0;
    c = rmw(0x72, 0, 0);
    expect("next CMD (SEQ 2) accepted once flash works", c.ack_st, UART_SIMPLE_OK);

    /* ---- Global invariant ---- */
    printf("\nInvariant:\n");
    expect("no (epoch, SEQ) ever reused by the master", nonce_reuse, 0);
    printf("    %d CMD nonces used, epochs %u..%u\n", n_used,
           (unsigned)used[0].epoch, (unsigned)EP.epoch);

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
