# Cipher brand

Black first. One geometric mark, one wordmark, one accent. Nothing decorative: no padlock, no shield, no gradient, no glow.

## The mark

An open ring (a "C") with a single square block in its opening. Built from one geometry (`assets/` files are generated from the same numbers: ring radius 30, stroke 12, an
opening of 92 degrees on the right, an 18 x 18 block centred in the opening). It reads at 24 px, works in one colour and on any background.

| File | Use |
| --- | --- |
| `assets/cipher-mark.svg` | Master: the mark on an ink tile (avatar, app tile, social profile) |
| `assets/cipher-mark-dark.svg` | Paper-white mark, transparent background, for DARK backgrounds |
| `assets/cipher-mark-light.svg` | Ink-black mark, transparent background, for LIGHT backgrounds |
| `assets/cipher-logo.svg` | Mark + wordmark on ink |
| `assets/cipher-logo-dark.svg`, `assets/cipher-logo-light.svg` | Lock-up on transparent, for dark and light backgrounds |
| `assets/cipher-banner.svg` | README banner |
| `assets/cipher-social-preview.png` (and `.svg`) | GitHub social preview, 1280 x 640. **Upload it by hand** in the repository's Settings > Social preview: GitHub offers no API for it. |
| `android/app/src/main/res/drawable/ic_launcher_fg.xml` | Adaptive-icon foreground, the Android 13+ themed (monochrome) icon and the Android 12+ splash icon |

The wordmark is drawn as paths (monoline geometric capitals), not as text, so it looks the same everywhere and needs no font.

## Colour

| Role | Dark | Light |
| --- | --- | --- |
| Background | `#0A0A0B` ink | `#F6F5F2` paper |
| Text | `#F4F4F5` | `#0E0E10` |
| Secondary text | `#A1A1A8` | `#55555C` |
| Surfaces | graphite `#151517` to `#242428` | white to `#E7E6E1` |
| Primary action | light `#EDEDEF` on ink | black `#0E0E10` on paper |
| Accent (selection, unread, verified) | steel blue `#8FA8C8` | `#3B5B82` |
| Warning | amber `#E2B45E` | `#8A5A00` |
| Error | `#F2877E` | `#B3261E` |

Amber means "needs attention", red means "failed or unsafe", the accent means "yours / selected / verified". The accent is never green, and it is used sparingly. Contrast pairs are
checked by `DesignTokensTest`.

## Shape and type

Small corners (4 to 16 dp), no shadows, no oversized cards. System sans-serif with a tuned scale (tight tracking on headlines, 12 sp minimum). Fingerprints and safety numbers are monospace.

## Do not

Do not recolour the mark, stretch it, add an outline, put it on a photograph, rotate the block, or add a padlock, shield or glow to it. Do not claim anything the product does not do
(`docs/EXPERIMENTAL_NOTICE.md`).
