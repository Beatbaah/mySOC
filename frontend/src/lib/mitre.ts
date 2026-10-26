// ATT&CK Enterprise tactics in kill-chain order.
export const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

export function techniqueUrl(id: string): string {
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) return ''
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
}
