export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'in_progress' | 'closed'
export type Disposition = 'true_positive' | 'false_positive' | 'benign'
export type CaseStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type Role = 'viewer' | 'analyst' | 'admin'

export interface UserRef { id: number; username: string; displayName: string }
export interface Me extends UserRef { role: Role; mfaEnabled: boolean; mustChangePassword: boolean }
export interface SessionState { user: Me; mfa: 'none' | 'verify' | 'enroll'; csrfToken: string }

export interface Alert {
  id: number
  ruleId: string
  title: string
  description: string
  severity: Severity
  riskScore: number
  status: AlertStatus
  disposition: Disposition | null
  srcIp: string
  dstIp: string
  dstPort: number
  protocol: string
  srcCountry: string
  mitreTactic: string
  mitreTechnique: string
  evidence: Record<string, unknown>
  count: number
  firstSeen: string
  lastSeen: string
  assignee: UserRef | null
  caseId: number | null
  closedAt: string | null
  closedBy: string | null
}

export interface Flow {
  id: number; start: string; end: string; srcIp: string; srcPort: number; dstIp: string; dstPort: number
  protocol: string; packets: number; bytes: number; tcpFlags: string; srcCountry: string; dstCountry: string
}

export interface Asset {
  id: number; ip: string; hostname: string; owner: string; criticality: 'low' | 'medium' | 'high' | 'critical'
  os: string; tags: string[]; firstSeen: string; lastSeen: string; openAlerts?: number
}

export interface Indicator {
  id: number; kind: 'ip' | 'domain' | 'hash' | 'url'; value: string; threat: string; source: string
  confidence: number; addedBy: string; createdAt: string; expiresAt: string | null; hits?: number
}

export interface Case {
  id: number; title: string; summary: string; severity: Severity; status: CaseStatus; owner: UserRef | null
  createdBy: string; tags: string[]; createdAt: string; updatedAt: string; resolvedAt: string | null; alertCount: number | null
}

export interface CaseEvent { id: number; at: string; actor: string; kind: string; body: string; data: Record<string, unknown> }

export interface LogEvent { id: number; at: string; sourceIp: string; host: string; app: string; severity: number; message: string }

export interface Sensor {
  name: string; source: string; online: boolean; lastSeen: string; startedAt: string
  stats: { flows?: number; logs?: number; alerts?: number; bytes?: number; flows_per_second?: number; queue?: number
    ml?: { trained: boolean; training_flows: number; anomalies: number }; capture_error?: string | null }
}

export interface Rule {
  id: string; name: string; kind: 'builtin' | 'match'; enabled: boolean; severity: Severity; description: string
  mitreTactic: string; mitreTechnique: string; params: Record<string, unknown>; updatedAt: string; updatedBy: string
  stats: { alerts7d?: number; falsePositives7d?: number; lastAlert?: string | null }
}

export interface UserRow extends Me { isActive: boolean; locked: boolean; createdAt: string; lastLoginAt: string | null }

export interface Page<T> { items: T[]; total?: number }
