# Default community relay (design; not deployed)

**Status: DESIGN ONLY. No default relay exists, and the project operates no infrastructure. Release builds ship with an empty default relay, a CI-enforced rule
(`android_guards.rs`). This document says what a default relay must be so that adding one later cannot make it an authority.**

## Purpose and non-purpose

Purpose: a person who does not run a server can install Cipher, tap "Create my identity" and talk to someone, with no setup. The code path exists (`OnboardingPlan`): when a
build carries a complete default relay (https URL and invitation code, optionally a certificate pin), the server step is skipped and "Use a different server" stays one
tap away.

Non-purpose: the default relay must **not** be required for identity, keys, contacts, or reaching people on other relays.

## Constraints (each is already true of the code)

| Constraint | Why it holds |
| --- | --- |
| It is not an identity authority | A Cipher identity is a key pair made on the phone; a relay holds public keys and ciphertext only (`MULTI_RELAY_PROTOCOL.md` §2). Another relay can be chosen at any time. |
| It is not a gateway to other relays | Contacts on any relay are added by card; the client reaches each relay directly; relays never talk to each other (§5). |
| No email, no phone number, no account page | Registration is an invitation code; an identity is a random id. |
| A relay operator is not the owner of anyone's keys | Private keys never leave the device; the vault is excluded from backup. |
| No silent enrolment | Nobody is added to a group or a community room without an explicit action (see `COMMUNITY_ROOMS.md`). |
| The operator can be discovered or pressured | The default relay is a public service run by an identifiable operator. A court order or a seizure can reveal its metadata (who registered when, who is addressed, sizes). It is not an anonymity tool; Tor hides addresses from it, not timing. |

## What the project would have to decide and do (not done)

1. **Who operates it**, under what name and jurisdiction, with what logging and retention (the relay's logs are already quiet: no addresses, minute-rounded times).
2. **Registration policy.** A public relay cannot keep its invitation code secret. Open registration needs abuse controls beyond the per-source and per-device limits that exist
   (quotas per account, a way to close registration quickly: `RELAY_ADMIN.md` provides the switch), and a statement of what happens to abusive accounts.
3. **Transport.** An onion service (`SELF_HOSTING.md` Profile A) with its pin shipped in the app avoids a public IP and DNS record for the operator. A clearnet name needs a CA
   certificate; a pin (`DEFAULT_RELAY_PIN`) is supported either way.
4. **Updates and key custody.** Changing the default relay's address needs a new app release; its pin must have a rotation plan (`SECURITY_TODO.md` ST-002).
5. **Capacity and abuse economics**, backups, an incident process, and a terms/privacy text that is reviewed by a lawyer (`PRIVACY_POLICY_DRAFT.md` is a draft).

## How it would be shipped without becoming mandatory

Build-time constants (`DEFAULT_RELAY_URL`, `DEFAULT_RELAY_PIN`, `DEFAULT_INVITE`) are the only place the default lives. The onboarding screen presents it as a choice; the
settings screen lets anyone add or switch relays; and nothing in the protocol, the vault or the contact format refers to it. Forks and self-hosters change three constants.
