# Quantic Sillage Desktop — visual acceptance gate

Status: NOT APPROVED. Development builds only; no user-facing installer delivery.

## Reference
Exact approved source: tableau_de_bord_quantic_sillage_européen.png
SHA-256: 1e23b69b11942e3cd31b6a87e15b8239c7dcee03008fcf9eafc8866542fd348b
Original dimensions: 1672 × 941 pixels.
The top institutional communication banner is not part of the application chrome.
The seven reference windows determine the desktop design; retain actual functionality,
do not embed their screenshots as interactive UI.

## Acceptance checks
- All seven pages captured from the same commit as the candidate installer.
- Home: compact dark navy sidebar, blue selection, official Q and separated circular dot,
  compact header, greeting, Earth banner, 3 × 2 service cards with correct sixth status card.
- Identity: blue identity card, separate action column, lower status area;
  no synthetic person's portrait or invented verified status.
- Mail: folders/navigation, message list and controls; no fabricated messages, notifications,
  delivery confirmations or unsupported active controls.
- Payments: distinct wallet overview, history and balance area; actual laboratory mode clearly
  labelled, no fictional monetary balance presented as real, no invented chart.
- Vault: storage summary and document table, functional add and retrieve controls.
- Protection: status summary and separate checks; unavailable tests must say unavailable.
- Settings: structured account, preferences, privacy, devices and about sections;
  no misleading functional claim.
- Match typography, margins, border radius, palette, iconography, proportions and visual hierarchy.
- Compare real captures at 100%, 125%, 150% Windows display scaling, plus narrow and wide
  client areas. Check text truncation, overlap, scrolling, keyboard navigation and action reachability.
- Never claim pixel-exactness from structural assertions alone. The raster concept contains
  fictional content and perspective effects; compare layout/style separately from real content.
- Record residual deviations explicitly. Any material mismatch blocks delivery.

## Current state
The previous ca4a2d3e build is NOT approved visually even though CI passed.
The new visual branch is a candidate, not an approved release. Reference contains an Earth
illustration crop of limited resolution; final visual fidelity and assets require inspection.
No automatic visual approval from successful CI. No user-facing executable until all
material mismatches have been resolved and the evidence has been inspected.
