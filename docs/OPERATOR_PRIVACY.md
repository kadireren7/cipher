# Running a relay: what you can learn, what others can learn

**Status: written from the code and the tests in this repository; self-reviewed only (ST-005). This is not legal advice and not an anonymity claim. Cipher does not make
anyone anonymous.**

## Who sees what

| Observer | Learns | Does not learn |
| --- | --- | --- |
| **Relay operator** (database, process, logs) | That an account exists, its public keys, the device list, mailbox ids, ciphertext sizes and arrival times, which mailbox a message was addressed to, group ids on the relay, invitation hashes. With clearnet access, the connecting IP address. | Message plaintext, group keys, private keys, contact names, the content of invitations and join requests. |
| **Relay operator who also watches the network** | Timing correlation between a sender's connection and a delivery. | Content. |
| **Hosting provider / network observer of an onion relay** | That the host runs Tor and carries traffic of some volume. | Which accounts exist, who talks, any address of a user. |
| **Network observer of a user's phone** | That Tor (or the chosen SOCKS route) is used and when. | The relay's identity if it is an onion service; the content. |
| **Another relay's operator** (cross-relay contact or group) | What the relay it serves sees of its own members' mailboxes. | Anything held only on the other relay. |
| **Someone with a stolen invitation link** | The group preview (name) and the right to *request* to join. | Membership or history; joining still needs the admin's approval by default (`INVITATIONS.md`). |

## What a relay stores, concretely

Accounts and devices (public keys), mailbox queues (opaque ciphertext until delivered or expired), blobs (encrypted), group routing rows, `SHA-256(invitation id)`
and sealed requests, coarse settings, and the administrator audit chain. Logs are quiet by design: no request bodies, no addresses, minute-rounded times
(`MAILBOX_PRIVACY.md`). Administration answers with coarse, identifier-free counts (`RELAY_ADMIN.md`).

## Recommendations for operators

* **Prefer the onion profile** (`SELF_HOSTING.md`, Profile A). You then hold no public IP, no DNS name and no certificate authority relationship, and users reach you through Tor.
* **Keep the administration layer off unless you need it**; when on it is loopback-only with its own secret.
* **Back up the database, not the secrets you do not need**, and test a restore. Keep `data/secrets` private (mode 600).
* **Retention**: queued messages expire; keep the defaults unless you have a reason.
* **Do not add analytics, access logs with addresses, or a reverse proxy that logs them.** Anything in front of the relay sees what the relay would have seen.
* **Closing registration** (`cipherctl.sh admin registration closed`) stops new accounts and leaves existing ones working.
* **Legal exposure**: operators of a public relay may receive requests for the metadata above. The honest answer is the table: ciphertext and routing metadata.
  Decide your logging and jurisdiction before you publish a relay for others.

## What is not claimed

No anonymity against a global or a relay-level timing observer, no protection of a compromised phone, no independent audit, no protection of metadata the relay needs to route
(who is addressed, when, how large). Push notifications are not implemented, so no third-party push service sees anything.
