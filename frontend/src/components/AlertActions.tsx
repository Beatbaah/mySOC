import { useState } from 'react'
import type { Disposition } from '../api/types'
import { Modal } from './ui'

const CHOICES: { value: Disposition; label: string; help: string }[] = [
  { value: 'true_positive', label: 'True positive', help: 'Real malicious or unwanted activity.' },
  { value: 'benign', label: 'Benign', help: 'The detection was right, but the activity is expected (e.g. an authorised scan).' },
  { value: 'false_positive', label: 'False positive', help: 'The detection was wrong. Consider tuning the rule.' },
]

export function CloseDialog({ count = 1, busy, onCancel, onConfirm }: {
  count?: number; busy?: boolean; onCancel: () => void; onConfirm: (d: Disposition) => void
}) {
  const [choice, setChoice] = useState<Disposition | null>(null)
  return (
    <Modal
      title={count > 1 ? `Close ${count} alerts` : 'Close alert'}
      onClose={onCancel}
      footer={
        <>
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className="btn primary" disabled={!choice || busy} onClick={() => choice && onConfirm(choice)}>Close</button>
        </>
      }
    >
      <fieldset style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 8 }}>
        <legend className="muted" style={{ marginBottom: 8 }}>What was it?</legend>
        {CHOICES.map((c) => (
          <label key={c.value} className="card" style={{ padding: '10px 12px', display: 'flex', gap: 10, cursor: 'pointer', borderColor: choice === c.value ? 'var(--accent)' : undefined }}>
            <input type="radio" name="disposition" checked={choice === c.value} onChange={() => setChoice(c.value)} />
            <span>
              <strong style={{ fontWeight: 500 }}>{c.label}</strong>
              <span className="muted" style={{ display: 'block', fontSize: 12 }}>{c.help}</span>
            </span>
          </label>
        ))}
      </fieldset>
    </Modal>
  )
}
