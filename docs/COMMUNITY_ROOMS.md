# Community rooms (design; not implemented)

**Status: DESIGN ONLY. Nothing here exists in the code, and no public-room UI may ship before the protocol below is implemented and tested.** Self-reviewed only.

## Three different things (never conflate them)

| | Relay registration | Public community room | Private E2EE group |
| --- | --- | --- | --- |
| What it is | An account on a relay (a key and a mailbox) | An optional, **labelled** public space attached to a relay | An MLS group with authenticated membership |
| Who can read | n/a | **The relay operator and anyone who joins.** Not end-to-end encrypted. | Members only |
| How you enter | An invitation code | An explicit "Join room" action | An admin's authorised Add (`INVITATIONS.md`) |
| What it proves | Nothing about identity | Nothing about identity | Authenticated membership |

A public room must never look like a private group: its screen says "Public room: anyone on this server can read this" permanently, uses a different icon and colour role
(the muted warning tone, not the accent), and never shows the verified badge.

## Why not an encrypted community room

An open, large, join-by-anyone room cannot be end-to-end encrypted in a meaningful way with the current design: MLS needs an authorised member to commit every Add, history
protection means every newcomer starts a new epoch, and a group of hundreds with churn would commit constantly and is exactly the partition and freeze problem already documented
(`CROSS_RELAY_GROUPS.md` §8, ST-051). The honest options are (a) a public, plaintext room, labelled, or (b) a **moderated** encrypted room, which is just a private group with an
invitation link (`INVITATIONS.md`). This design chooses (a) for open communities and tells people to use (b) for anything private.

## Public room protocol (sketch)

* A room is a row on the relay: an id, a display name, a description, a creator **device** (not account) and a posting policy. The relay stores plaintext messages with a short
  retention (default 7 days). The operator can read, delete and ban; this is stated in the room header.
* Joining is an authenticated, explicit request that adds the device to the room's reader/poster list. **Nobody is joined by default and no one is auto-enrolled**, including at
  registration.
* Posting is signed by the device key (so a relay cannot forge a post *as a member* to other members' clients, but it can drop, reorder or invent posts in a plaintext room:
  there is no confidentiality and only device-level authenticity).
* **Abuse and a single bad actor.** One malicious member must not be able to disable the room: per-device post rate limits and size limits at the relay; moderators (a list of device
  keys set by the room creator) can delete posts and mute devices; a mute is by device key and expires; the relay operator can close the room. There is no state that a member can
  corrupt for others (no MLS commit, no shared key), which is the main reason for choosing plaintext rooms.
* **Metadata**: the relay sees who reads and posts and when. Over Tor it does not see addresses.

## Tests that must exist before any UI

Authorisation of every endpoint (a non-member cannot read or post; a moderator can only moderate its own rooms), no room appears in the conversation list without an explicit
join, no registration path joins a room, rate limits per device, a muted device cannot post, retention purge, and a screenshot test that every room screen carries the public label.
