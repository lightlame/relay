import { useEffect, useMemo, useState } from "react";
import { Icon, type IconName } from "./Icon";

export interface PaletteCommand {
  id: string;
  title: string;
  group: string;
  icon: IconName;
  hint?: string;
}

interface CommandPaletteProps {
  open: boolean;
  commands: PaletteCommand[];
  onClose: () => void;
  onAction: (id: string) => void;
}

export function CommandPalette({ open, commands, onClose, onAction }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return commands;
    return commands.filter((command) => `${command.title} ${command.group}`.toLowerCase().includes(needle));
  }, [commands, query]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  if (!open) return null;

  return (
    <div className="overlay" onMouseDown={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-label="Command palette"
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            setActive((value) => Math.min(matches.length - 1, value + 1));
          }
          if (event.key === "ArrowUp") {
            event.preventDefault();
            setActive((value) => Math.max(0, value - 1));
          }
          if (event.key === "Enter" && matches[active]) {
            event.preventDefault();
            onAction(matches[active].id);
            onClose();
          }
        }}
      >
        <div className="palette-search">
          <Icon name="command" />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Run a command…"
          />
          <kbd>ESC</kbd>
        </div>
        <div className="palette-label">COMMANDS</div>
        {matches.map((command, index) => (
          <button
            key={command.id}
            className={`palette-action ${index === active ? "active" : ""}`}
            onMouseEnter={() => setActive(index)}
            onClick={() => {
              onAction(command.id);
              onClose();
            }}
          >
            <span className="palette-action-title">
              <Icon name={command.icon} />
              {command.title}
            </span>
            <small>
              {command.hint ?? command.group}
            </small>
          </button>
        ))}
        {!matches.length && <div className="palette-empty">No command matches “{query}”</div>}
      </div>
    </div>
  );
}
