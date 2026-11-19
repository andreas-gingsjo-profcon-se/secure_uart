# uart_simple: secure read-modify-write polling

`uart_simple.[ch]` adds authentication, encryption and replay protection to the
master/slave polling cycle on the shared 4800-baud bus. It is designed to fit
the cycle-time budget: **252 slaves, one read-modify-write (RMW) each, within 30 s.**

The master reads each slave's status, computes a command from that status plus
its own state (`S_STATUS + M_STATE → S_COMMAND`), and sends the command.

---

## 1. Design idea: deferred status authentication

A tag on every frame costs too much at 4800 baud. Instead, the read half of the
cycle carries no cryptographic bytes, and the status is authenticated later,
inside the command's tag.

```
M → S   READ                       plaintext, CRC-16
S → M   STATUS | s                 plaintext, CRC-16   slave remembers snapshot s
M → S   CMD    | c | TAG           AES-CCM; AAD contains s' (status as the master received it)
S → M   ACK    | r | TAG           AES-CCM; AAD contains s and c
```

The status `s` is never sent twice. Both sides feed it into the MAC: the master
uses what it received (`s'`), the slave uses the snapshot it sent (`s`).

### Why an unauthenticated READ/STATUS is safe

| Attack | Effect |
|---|---|
| STATUS altered or replayed on the wire | Master computes the CMD tag over the wrong `s'`. Slave verifies against its real `s`, the tag fails and the command is never executed. Equivalent to jamming. |
| Forged READ | Slave transmits its status (already visible on the bus) and refreshes its snapshot. READ has no other side effects and advances no counter. |
| Forged status influencing *other* slaves via `M_STATE` | Prevented by rule: the master treats a status as **provisional** until that slave's authenticated ACK arrives, and only then folds it into `M_STATE`. |

### Atomic RMW for free

When verifying a CMD, the slave also checks `snapshot == current status`. If the
status changed between READ and CMD, the command is authentic but **not
executed**, and the slave answers with an authenticated `STALE` ACK. The
read-then-act race of the unsecured system is closed.

---

## 2. Wire format

```
SOF | ADDR | CTRL | BODY | trailer
CTRL = TYPE (bits 7..6) | LEN (bits 5..0)      LEN = body length, max 63
```

| TYPE | Frame | Body | Trailer |
|---|---|---|---|
| 0 | READ | empty | CRC-16 |
| 0 | ANNOUNCE | `EPOCH (4, LE) \| SEQ (4, LE)` | 4-byte tag |
| 1 | STATUS | status bytes (plaintext) | CRC-16 |
| 2 | CMD | encrypted command | 4-byte tag |
| 3 | ACK | encrypted result (1 byte) | 4-byte tag |

- `SOF = 0x7E`.
- CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over `ADDR | CTRL | BODY`, sent big-endian.
  It only detects line errors; it is **not** a security mechanism.
- The CCM tag replaces the CRC on CMD and ACK; it also detects line errors.
- Tag size `UART_SIMPLE_TAG_SIZE` is 4 bytes by default (CCM allows 4, 6, 8, …, 16).

ACK result values: `0 EXECUTED`, `1 STALE` (status changed, not executed),
`2 REJECTED` (application refused).

### Example cycle (4-byte status, 2-byte command)

```
READ    ( 5 B): 7e 2a 00 f4 22
STATUS  ( 9 B): 7e 2a 44 01 00 10 20 74 d1
CMD     ( 9 B): 7e 2a 82 c3 2f 0b 07 5c 7a
ACK     ( 8 B): 7e 2a c1 87 c8 d9 34 cf
```

---

## 3. Cryptography

AES-128-CCM, one key per slave.

```
Nonce (13 B) = TYPE | ADDR | EPOCH (4, LE) | SEQ (4, LE) | 00 00 00

CMD AAD      = ADDR | CTRL | len(s) | s
ACK AAD      = ADDR | CTRL | len(s) | s | len(c) | c
ANNOUNCE AAD = ADDR | CTRL | EPOCH | SEQ        (no ciphertext, tag only)
```

- The nonce TYPE for ANNOUNCE is 4 (not a CTRL type), so it can never collide
  with a CMD or ACK nonce.
- CMD and ACK share `(EPOCH, SEQ)` but differ in TYPE.
- **Status is not confidential.** It travels in plaintext; integrity and
  freshness are still guaranteed. Commands and ACK results are encrypted.

---

## 4. EPOCH + SEQ: nonce and replay management

Neither EPOCH nor SEQ is transmitted in CMD or ACK frames. Both sides track them.

| | Master | Slave |
|---|---|---|
| EPOCH | ATECC608 monotonic counter | Flash (written via callback) |
| SEQ | One 32-bit counter per slave in battery-backed RAM | RAM only |

**Invariant:** the master never uses the same `(EPOCH, SEQ)` twice under one key,
whatever happens to its battery-backed RAM.

### 4.1 Master boot (`uart_simple_epoch_boot`)

Battery-backed RAM layout (`uart_simple_bbram_t`):
`magic | epoch | n_slaves | check | seq[n_slaves]`.

1. Read the hardware counter.
2. If the header is valid **and** its epoch equals the counter, resume.
3. Otherwise (VBAT lost, tamper erase, crash during an update):
   1. Invalidate the header.
   2. **Increment the hardware counter**. This happens before any frame is sent.
   3. Set every SEQ to 0, write the new epoch, re-validate the header.

A crash anywhere in step 3 leaves the header invalid, so the next boot simply
bumps again. Skipped epochs are harmless.

### 4.2 Epoch bump (`uart_simple_epoch_bump`)

Same steps as 3.1–3.3. Use it when:

- a slave has rebooted (it refuses the current epoch, see 4.4), or
- a slave's SEQ reaches 2³² − 1 (`UART_SIMPLE_ERR_SEQ`).

**The application must rate-limit bumps** (for example at most one per minute,
batching all pending reasons). The ATECC608 counter allows about 2.1 million
increments; an attacker who can suppress ACKs could otherwise trigger bumps
and burn through it. At one bump per minute, exhaustion takes about 4 years
even under continuous attack. Unusually frequent bumps are themselves a sign
of an attack and should raise an alert.

### 4.3 Slave CMD acceptance

A CMD is tried against these candidate nonces, in order:

```
(E,   last_seq+1 … last_seq+W)    only if the slave's SEQ state is valid
(E+1, 1 … W)                      master bumped once
(E+2, 1 … W)                      master bumped twice while this slave wasn't listening
```

`W = UART_SIMPLE_SEQ_WINDOW = 8` (tolerates up to 7 consecutive lost CMDs).
Lookahead = `UART_SIMPLE_EPOCH_LOOKAHEAD = 2`.

- Slaves follow a master bump **automatically, with no extra frames**.
- Entering a new epoch calls the persist callback **before** the command is
  executed. If the flash write fails, the command is not executed
  (`UART_SIMPLE_ERR_PERSIST`).
- An authentic command always consumes its SEQ, even when it is not executed
  (STALE). Otherwise it could be replayed later when the status happened to
  match again.
- Exactly one ACK is sent per accepted `(EPOCH, SEQ)`.

### 4.4 Slave reboot

The slave keeps only EPOCH in flash. After a reboot it does not know which SEQ
values it has already accepted, so it **refuses its stored epoch entirely**. It
accepts only `E+1` or later.

The master notices because that slave stops sending ACKs, bumps the epoch, and
all slaves follow on their next CMD. No SYNC exchange and no random number
generator on the slave are needed for this.

### 4.5 ANNOUNCE (slave more than 2 epochs behind)

A slave that missed three or more bumps (for example it was powered off) cannot
find the epoch with its lookahead. The master then sends an ANNOUNCE instead of
a READ:

```
M → S   ANNOUNCE | EPOCH | SEQ | TAG     (15 B)
S → M   STATUS   | s                     (normal STATUS: the cycle continues as usual)
```

- The ANNOUNCE consumes a fresh SEQ, so its nonce is unique.
- It is accepted only if its EPOCH is **strictly greater** than the slave's
  stored epoch. An old ANNOUNCE can never rewind a slave, and after a reboot
  the stored epoch remains refused (only a bump helps).

### 4.6 Recommended master policy for a slave that stops ACKing

1. Retry the cycle.
2. Send an ANNOUNCE (fixes a slave that is far behind).
3. Bump the epoch, subject to the rate limit (fixes a slave that rebooted).

The master cannot distinguish the last two cases; this order handles both.

### 4.7 Commissioning

When a slave gets a new key, the master gives it the current epoch, the slave
calls `uart_simple_slave_init(.., stored_epoch, fresh_key = 1, ..)`, and the
master resets that slave's SEQ slot to 0. Reusing SEQ values is safe here
because the key is new.

---

## 5. API

### Master

```c
/* Once at boot, before any frame */
uart_simple_epoch_boot(&ep, &counter_ops, bbram, n_slaves, &bumped);

/* One context per slave */
uart_simple_master_init(&m, key, addr, &ep, slot);

/* Each cycle */
uart_simple_master_build_read(&m, buf, &len);        /* or _build_announce() */
uart_simple_master_handle_status(&m, rx, rx_len);    /* m.status = PROVISIONAL */
/* compute command from m.status + M_STATE */
uart_simple_master_build_cmd(&m, cmd, cmd_len, buf, &len);
uart_simple_master_handle_ack(&m, rx, rx_len, &result);
/* UART_SIMPLE_OK: m.status is now CONFIRMED -> fold into M_STATE */
```

Hardware hooks (`uart_simple_counter_ops_t`): `read(user, &value)` and
`increment(user, &new_value)`, mapped to the ATECC608 Counter command.

### Slave

```c
uart_simple_slave_init(&s, key, addr, flash_epoch, fresh_key, persist_fn, user);

/* READ or ANNOUNCE */
uart_simple_slave_handle_read(&s, rx, rx_len, status, status_len, tx, &tx_len);

/* CMD */
st = uart_simple_slave_handle_cmd(&s, rx, rx_len, cur_status, cur_len, cmd, &cmd_len);
if (st == UART_SIMPLE_OK)         { execute(cmd); build_ack(&s, UART_SIMPLE_RES_EXECUTED, ..); }
else if (st == UART_SIMPLE_ERR_STALE) {          build_ack(&s, UART_SIMPLE_RES_STALE, ..); }
else                              { /* drop silently, send nothing */ }
```

Dispatch helpers: `uart_simple_frame_type()`, `uart_simple_frame_addr()`.
Frames for other addresses return `UART_SIMPLE_ERR_ADDR` before any crypto runs.

---

## 6. Timing budget (4800 baud, 8N1)

| | Bytes |
|---|---|
| READ | 5 |
| STATUS (4-byte status) | 9 |
| CMD (2-byte command) | 9 |
| ACK | 8 |
| **Per RMW cycle** | **31** |

- 252 slaves × 31 B = **about 16.3 s on the wire**, excluding line turnaround.
- 1,008 frames per cycle: each 1 ms of turnaround per frame adds about 1 s.
- Compared with a tag on every frame (CRC-16 replaced by a 4-byte tag on all
  four frames), this saves 4 bytes per RMW cycle.
- An ANNOUNCE (15 B) replaces a READ (5 B) only for slaves that are far behind.

---

## 7. Hardware mapping

### Master: STM32H747 + ATECC608

| Need | Where |
|---|---|
| Per-slave SEQ table | Backup SRAM (VBAT domain). Configure tamper detection to erase it; recovery then follows 4.1. |
| EPOCH | ATECC608 monotonic counter |
| AES-CCM | Mbed TLS in software (the H747 has no CRYP/HASH peripheral; the H757 does). Far faster than the bus requires. |
| Per-slave keys at rest | Encrypted in STM32 flash with a key held in the ATECC608; RDP level 2 and write-protected bootloader |

### Slave: MSPM0G1519

| Need | Where |
|---|---|
| AES-CCM | AESADV accelerator (CCM supported, 4-byte tags). Replace the Mbed TLS calls in `ccm_seal` / `ccm_open` and the CMD candidate loop. |
| Slave key | Firewall-protected data flash, loaded into the keystore by the customer secure code (CSC) at boot |
| EPOCH | Data flash (persist callback). Written only when the epoch changes. |
| Debug | Lock SWD in NONMAIN for production (an invalid NONMAIN configuration can brick the device) |

---

## 8. Test coverage (`simple_example.c`)

`make test` runs it. All checks pass.

| Scenario | Expected result |
|---|---|
| Normal cycle | Executed, ACK verified |
| Replayed CMD after a fresh READ | Rejected, not executed |
| CMD based on a forged STATUS | Rejected by the slave, no ACK |
| Status changes between READ and CMD | STALE ACK, not executed |
| Lost CMD | Next CMD accepted within the SEQ window |
| Forged ACK | Rejected by the master |
| CMD without a preceding READ | Refused by the master |
| Frame for another address | Ignored before crypto |
| Master reboot, battery-backed RAM intact | No bump, resumes |
| **VBAT loss** | Epoch bumped; slave follows silently; old-epoch CMD rejected |
| Crash after counter increment, before header write | Bumps again (E+2); slave follows silently |
| **Slave reboot** | Current epoch refused; pre-reboot CMD can't be replayed; ANNOUNCE for current epoch refused; works after a bump |
| Slave 3 epochs behind | Plain CMD rejected; ANNOUNCE + CMD accepted |
| Replayed or tampered ANNOUNCE | Rejected |
| Slave flash write fails | Command not executed; recovers once flash works |
| **Global invariant** | No `(EPOCH, SEQ)` ever reused by the master |

---

## 9. Residual risks and limits

- **Forgery odds.** With the full candidate set, a forged CMD gets
  `(1 + LOOKAHEAD) × W = 24` attempts against a 32-bit tag, about 2⁻²⁷·⁴ per
  frame. Reduce `UART_SIMPLE_SEQ_WINDOW` or `UART_SIMPLE_EPOCH_LOOKAHEAD`, or
  increase the tag size, if that is too generous. Add a delay after
  authentication failures on the slave; avoid a hard lockout, which an attacker
  could trigger deliberately.
- **Delayed delivery.** An attacker who blocks a CMD or ANNOUNCE and delivers it
  later can get a genuine but older command executed. This only works if the
  slave's status still equals the status the command was computed for, and the
  master detects it because the ACK will not verify against its pending SEQ.
  Any sliding-window scheme has this property.
- **Status is plaintext.** If status confidentiality is required, it cannot use
  a slave-side counter as nonce (unauthenticated READs could make it repeat).
  Option: a per-boot random value from the slave TRNG, learnt by the master,
  plus a 1-byte read counter on the wire (+1 B per STATUS).
- **Line noise on STATUS** surfaces as a failed CMD instead of a CRC retry; the
  master has to repeat READ, STATUS and CMD.
- **Lost ACK.** The command may or may not have executed. Never resend a CMD
  with the same SEQ; the next cycle's READ shows the slave's actual state.
- **Body size** is limited to 63 bytes per frame (6-bit LEN).

## 10. Not implemented

- Porting the slave side from Mbed TLS to the MSPM0 AESADV and keystore.
- Bump rate limiting and the policy in 4.6 (application responsibility).
- Commissioning (ECDH key agreement during the "Who wants 00:01?" exchange).
