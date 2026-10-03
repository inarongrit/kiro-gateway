# Portal design system — "Kiro Gateway"

One visual language for the whole portal: APISIX's existing pages, the new AI Guardrails and
Observability pages, and the charts. Implemented as a Mantine theme (`theme.ts` here, applied in
Stage 3) plus a matching antd `ConfigProvider` token set, because some upstream pages use antd.

## Principles
1. **Calm by default, loud when it matters.** Neutral surfaces; colour is reserved for state
   (blocked = red, allowed = green, rate-limited = amber) and for the single primary action.
2. **Glanceable first, detail on demand.** Every card answers one question in its title
   ("What got blocked?"), shows one number or chart, and links to the page with the full story.
3. **One motion vocabulary.** 150 ms for hover/press, 220 ms for panels and drawers, ease-out.
   Respect `prefers-reduced-motion` (no transitions, no animated counters).
4. **Accessible contrast in both themes.** Body text ≥ 4.5:1, large numbers and UI ≥ 3:1,
   state never shown by colour alone (icon + label).

## Tokens
| Token | Dark (default) | Light |
|---|---|---|
| `bg/canvas` | `#0B0E14` | `#F6F7FB` |
| `bg/surface` (cards) | `#121722` | `#FFFFFF` |
| `bg/raised` (popovers, hover) | `#1A2130` | `#F0F2F8` |
| `border/subtle` | `#232B3B` | `#E3E7F0` |
| `text/primary` | `#E8ECF4` | `#121722` |
| `text/secondary` | `#9AA4B8` | `#5B6478` |
| `brand` (primary, links, focus) | `#7C8CFF` (indigo 400) | `#4C5BD4` (indigo 600) |
| `state/allowed` | `#34D399` | `#0F9D6E` |
| `state/blocked` | `#F87171` | `#D93A3A` |
| `state/limited` | `#FBBF24` | `#B7791F` |
| `state/info` | `#38BDF8` | `#0B84C6` |
| `chart` series 1–6 | indigo, teal, violet, sky, amber, rose (400 dark / 600 light) | |

- **Type:** Inter Variable (self-hosted via `@fontsource-variable/inter`, no CDN), tabular numbers for
  metrics. Scale 12 / 13 / 14 (body) / 16 / 20 / 24 / 32 (KPI). Mono: JetBrains Mono for patterns,
  IDs and prompts.
- **Spacing:** 4-px grid; card padding 20, grid gap 16, page padding 24.
- **Radius:** 8 inputs and buttons, 12 cards, 999 pills.
- **Elevation:** dark uses borders + a faint inner highlight, not shadows; light uses
  `0 1px 2px rgba(16,24,40,.06), 0 1px 3px rgba(16,24,40,.10)`.
- **Icons:** Tabler (already used upstream through `unplugin-icons`), 18 px in nav, 16 px inline.
- **Charts:** `@mantine/charts` (Recharts) with the series palette above, 2 px lines, area fill at
  15 %, no chart borders, gridlines `border/subtle`, tooltips on `bg/raised`.

## Layout
- App shell: 248 px sidebar (collapsible to a 64 px icon rail), 56 px header.
- Sidebar groups: **Overview** · **AI Guardrails** (Rules, Activity, Prompt tester) ·
  **Observability** (Traffic, Latency, Usage, Traces) · **Gateway** (APISIX's existing pages:
  Routes, Services, Upstreams, Consumers, SSL, Plugins, …).
- Header: environment badge, gateway health, global time range, search (Ctrl/⌘ K), theme toggle,
  user menu (sign-out = console sign-out).
- Content max width 1440 px; 12-column card grid, collapsing to 1 column below 900 px.
