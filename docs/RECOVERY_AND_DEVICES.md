# Recovery, device lists and device revocation (ST-010, ST-020, ST-033)

## Recovery — decision: **No cryptographic recovery available.**
Cipher does not offer account recovery. Identity keys are generated on the device, never leave it, and the vault is bound to a Keystore key. Losing the phone (or an invalidated Keystore key) loses the identity; the user starts a new one and contacts must re-verify.
Rejected on purpose: email/SMS reset, security questions, server-held or escrowed keys, cloud backup of the vault (backup is disabled in the manifest). Each of these lets someone other than the device holder impersonate the user or decrypt, i.e. weakens the model. A user-held recovery secret (e.g. a printed high-entropy code) has not been designed or reviewed; if ever added it needs ST-005-level review first. Onboarding already tells the user this; key loss never triggers an automatic wipe (tested).

## Devices today
One device per account. There is no linked-device protocol and no message/state sync (ST-020). Consequences:
* **Visible device list:** the app shows *contacts'* device-list changes (`DEVICE_LIST_CHANGED`, `UNENDORSED_DEVICE`); a user has exactly one device of their own, so there is no list to manage.
* **Revoking another device:** impossible to meaningfully offer — there is no other device of the same account. Group-level removal of an *account* removes all its devices (REV-008).
* A device record stays in the relay directory until the account is abandoned (ST-033, low severity: it is only a routing endpoint without keys).
* **Identity is never rotated silently:** a changed identity key is surfaced as `IDENTITY_CHANGED` and never auto-accepted.

## Constraints for a future multi-device design (for review)
1. Adding a device must be authorised by an existing device (signed endorsement, already modelled by `UNENDORSED_DEVICE`).
2. Revoking device X = MLS Remove of X's leaf in every group + a signed revocation visible to contacts + a visible security event; X receives no later epoch secrets (the REV-009 property, then tested with two real devices).
3. History on a revoked device follows the group-removal rules (history keys deleted when it observes revocation); an account-level removal must remove all devices (REV-008) and needs an engine-level two-device test.
4. Recovery after losing *all* devices remains impossible without a user-held secret.
