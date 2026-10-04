# Delivery states (ST-032) — what each state does and does not prove

| State | Meaning | Who attests | Forgeable by the relay? |
| --- | --- | --- | --- |
| `Pending` | Encrypted, waiting in the local outbox | this device | n/a |
| `Sent` | The relay answered 2xx to the send/batch request | the relay | **yes** — it may say "accepted" and drop |
| `Delivered` | An end-to-end *receipt frame* (inside MLS, authenticated by the recipient's leaf) naming the message id arrived | the recipient's device, after decrypting | **no** (the relay cannot create or alter MLS application messages) |
| `Failed` | Retries exhausted | this device | n/a |

* A relay acknowledgement (`ack`, queue deletion) is never treated as a receipt (REV-010; test `a_fake_acknowledgement_does_not_make_a_message_delivered`).
* "Read" receipts do not exist; receipts mean *decrypted by the recipient's device*, not *seen by a human*.
* Receipts are implemented for DMs only. Group delivery state is not tracked per member.
* **Not provided:** detection of a relay that silently drops or delays messages (ST-032). The sender sees `Sent` forever; a missing receipt is *not* proof of dropping (the peer may be offline). A gap-detection design (sender counters inside the E2EE frame, UI warning) needs a frame-format change and an independent channel to be meaningful — deliberately not half-built (ADR-036).
