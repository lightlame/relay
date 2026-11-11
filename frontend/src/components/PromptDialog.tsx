import { useEffect, useRef, useState } from "react";
import { Icon } from "./Icon";

interface PromptDialogProps {
  open: boolean;
  title: string;
  description: string;
  label: string;
  placeholder: string;
  initialValue?: string;
  confirmLabel: string;
  onClose: () => void;
  onSubmit: (value: string) => void;
}

export function PromptDialog(props: PromptDialogProps) {
  const { open, title, description, label, placeholder, initialValue = "", confirmLabel, onClose, onSubmit } = props;
  const [value, setValue] = useState(initialValue);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setValue(initialValue);
      window.setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open, initialValue]);

  if (!open) return null;

  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
  };

  return (
    <div className="overlay prompt-overlay" onMouseDown={onClose}>
      <div className="prompt-dialog" role="dialog" aria-label={title} onMouseDown={(event) => event.stopPropagation()}>
        <div className="settings-head">
          <div>
            <div className="eyebrow">RELAY</div>
            <h2>{title}</h2>
            <p>{description}</p>
          </div>
          <button className="icon-button" onClick={onClose} title="Close">
            <Icon name="close" />
          </button>
        </div>
        <div className="prompt-body">
          <label className="prompt-field">
            {label}
            <input
              ref={inputRef}
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={placeholder}
              onKeyDown={(event) => {
                if (event.key === "Enter") submit();
              }}
            />
          </label>
          <div className="settings-actions">
            <button className="primary-button" onClick={submit} disabled={!value.trim()}>
              <Icon name="check" /> {confirmLabel}
            </button>
            <button className="quiet-button" onClick={onClose}>
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
