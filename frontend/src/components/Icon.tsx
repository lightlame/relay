export const icons = {
  traffic: "↯",
  drafts: "◇",
  collections: "▤",
  history: "◷",
  search: "⌕",
  play: "▶",
  stop: "■",
  sun: "☼",
  moon: "◐",
  filter: "≡",
  close: "×",
  copy: "⧉",
  more: "···",
  chevron: "⌄",
  back: "←",
  command: "⌘",
  check: "✓",
  error: "!",
  empty: "∅",
  download: "↓",
  settings: "⚙",
  trash: "⌫",
  plus: "+",
  external: "↗",
  clock: "◷",
  lock: "⚿",
  eye: "◉",
  layers: "▥",
} as const;

export type IconName = keyof typeof icons;

export function Icon({ name, className = "" }: { name: IconName; className?: string }) {
  return (
    <span className={`icon ${className}`} aria-hidden="true">
      {icons[name]}
    </span>
  );
}
