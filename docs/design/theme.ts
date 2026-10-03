/**
 * Portal theme (draft from Stage 2; wired into src/main.tsx in Stage 3).
 * Mirrors docs/design/DESIGN.md. Light/dark values come from CSS variables so the
 * same theme drives both colour schemes (Mantine `defaultColorScheme="dark"`).
 */
import { createTheme, type MantineColorsTuple, rem } from '@mantine/core';

const indigo: MantineColorsTuple = [
  '#EEF0FF', '#DDE1FF', '#BAC2FF', '#98A3FF', '#7C8CFF',
  '#6575F5', '#4C5BD4', '#3D49AE', '#2F3888', '#222863',
];

export const portalTheme = createTheme({
  primaryColor: 'indigo',
  colors: { indigo },
  primaryShade: { light: 6, dark: 4 },
  fontFamily: '"Inter Variable", Inter, system-ui, -apple-system, "Segoe UI", sans-serif',
  fontFamilyMonospace: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
  headings: { fontWeight: '650', sizes: { h1: { fontSize: rem(24) }, h2: { fontSize: rem(20) }, h3: { fontSize: rem(16) } } },
  fontSizes: { xs: rem(12), sm: rem(13), md: rem(14), lg: rem(16), xl: rem(20) },
  defaultRadius: 'md',
  radius: { sm: rem(6), md: rem(8), lg: rem(12), xl: rem(16) },
  spacing: { xs: rem(8), sm: rem(12), md: rem(16), lg: rem(20), xl: rem(24) },
  cursorType: 'pointer',
  focusRing: 'auto',
  respectReducedMotion: true,
  other: {
    state: { allowed: 'var(--kg-allowed)', blocked: 'var(--kg-blocked)', limited: 'var(--kg-limited)', info: 'var(--kg-info)' },
    motion: { fast: '150ms', panel: '220ms', easing: 'cubic-bezier(.2,.8,.2,1)' },
  },
  components: {
    Card: { defaultProps: { radius: 'lg', padding: 'lg', withBorder: true } },
    Paper: { defaultProps: { radius: 'lg' } },
    Button: { defaultProps: { radius: 'md' } },
    Badge: { defaultProps: { radius: 'xl', variant: 'light' } },
    Tooltip: { defaultProps: { withArrow: true, openDelay: 250 } },
  },
});

/** CSS variables for both schemes (injected via MantineProvider cssVariablesResolver in Stage 3). */
export const portalCssVars = {
  dark: {
    '--kg-canvas': '#0B0E14', '--kg-surface': '#121722', '--kg-raised': '#1A2130', '--kg-border': '#232B3B',
    '--kg-text': '#E8ECF4', '--kg-text-2': '#9AA4B8',
    '--kg-allowed': '#34D399', '--kg-blocked': '#F87171', '--kg-limited': '#FBBF24', '--kg-info': '#38BDF8',
  },
  light: {
    '--kg-canvas': '#F6F7FB', '--kg-surface': '#FFFFFF', '--kg-raised': '#F0F2F8', '--kg-border': '#E3E7F0',
    '--kg-text': '#121722', '--kg-text-2': '#5B6478',
    '--kg-allowed': '#0F9D6E', '--kg-blocked': '#D93A3A', '--kg-limited': '#B7791F', '--kg-info': '#0B84C6',
  },
} as const;
