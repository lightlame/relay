import { useState } from "react";
import { Icon } from "./Icon";
import type { Collection } from "../types";

interface FolderDialogProps {
  open: boolean;
  selectedCount: number;
  collections: Collection[];
  onClose: () => void;
  onSaveToExisting: (collection: Collection) => void;
  onCreate: (name: string) => void;
}

export function FolderDialog(props: FolderDialogProps) {
  const { open, selectedCount, collections, onClose, onSaveToExisting, onCreate } = props;
  const [name, setName] = useState("");

  if (!open) return null;

  const create = () => {
    const value = name.trim();
    if (!value) return;
    onCreate(value);
    setName("");
  };

  return (
    <div className="overlay folder-overlay" onMouseDown={onClose}>
      <div className="folder-dialog" role="dialog" aria-label="Save selection to folder" onMouseDown={(event) => event.stopPropagation()}>
        <div className="settings-head">
          <div>
            <div className="eyebrow">COLLECTIONS</div>
            <h2>Save {selectedCount} selected request{selectedCount === 1 ? "" : "s"}</h2>
            <p>Choose an existing folder or create a new one. Originals stay in the capture session.</p>
          </div>
          <button className="icon-button" onClick={onClose} title="Close">
            <Icon name="close" />
          </button>
        </div>

        <div className="folder-body">
          <div className="block-heading">Existing folders</div>
          {collections.length === 0 && <div className="inline-empty">No folders yet. Create the first one below.</div>}
          <div className="folder-list">
            {collections.map((collection) => (
              <button className="folder-row" key={collection.id} onClick={() => onSaveToExisting(collection)}>
                <Icon name="collections" />
                <div>
                  <strong>{collection.name}</strong>
                  <small>{collection.exchangeIds.length} requests</small>
                </div>
                <span className="text-button">Save here</span>
              </button>
            ))}
          </div>

          <div className="block-heading folder-new-title">New folder</div>
          <div className="folder-create">
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Folder name"
              onKeyDown={(event) => {
                if (event.key === "Enter") create();
              }}
            />
            <button className="primary-button" onClick={create} disabled={!name.trim()}>
              <Icon name="plus" /> Create
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
