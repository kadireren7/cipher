# Cipher privacy policy — DRAFT

**Status: draft written by the engineering team. Not reviewed by a lawyer. Do not publish as-is.** Placeholders in `[brackets]` need the publisher's decision.
It describes what the software does today; if the software changes, this text must change. It makes no anonymity promise.

## Who is responsible
Cipher is software, not a service. There is no central Cipher server. Each person chooses a **relay** (a server run by themselves or someone they trust). The party that runs your relay is the controller of whatever the relay stores. The publisher of the app, `[publisher legal name and contact]`, operates no relay by default and receives no data from the app. The app contains no analytics, advertising or crash-reporting SDK (enforced by a CI guard).

## What stays on your phone
Message text, attachments, contact names and your identity keys are stored encrypted on your phone. Keys are held in the Android Keystore. Cipher excludes its data from Android backups and cloud transfer. If you lose or reset the phone, the data is gone; there is no recovery.

## What your relay can see and store
| Data | Why | How long |
| --- | --- | --- |
| Encrypted message and attachment bytes (padded; the relay cannot read them) | to deliver them | until delivered, or at most the relay's TTL (default 7 days, maximum 30) |
| Your account and device identifiers and public keys | to let others reach you | until you or the operator delete the account |
| Who a message is addressed to, and when it was sent and fetched; approximate sizes | to deliver and rate-limit | queue lifetime; request logs are off by default and rounded to the minute when on |
| A keyed hash of your network address | abuse limits | about 24 hours |
| Push registration token, only if you enable push | to wake the app | until you disable push |
Your relay does **not** receive your contacts, message content, attachment names or types, or the content of group names.
When you message someone on a different relay, **their** relay sees that a message arrived for them, its size and the time. It does not see your account.

## What a network observer can see
Your internet provider can see that you connect to your relay (or to Tor) and when. Cipher protects content, not the fact of communication. Tor, if you use it, hides the relay's address from your provider and your address from the relay; it does not stop a global observer correlating timing.

## Push notifications (optional, off by default)
Not available in this version. When added, the push provider will learn the time of each wake-up and a device endpoint, never message content. See `NOTIFICATIONS.md`.

## Permissions
Camera (scan contact codes), microphone (voice notes, only while recording), notifications. No contacts, location, storage or phone permissions.

## Your choices and rights
Delete a message, conversation or all local data in the app. Ask your relay operator to delete your account. `[Jurisdiction-specific rights, contact, retention for any publisher-held data (none today)]`.

## Children, changes, contact
`[Minimum age]`, `[how changes are announced]`, `[contact]`.
