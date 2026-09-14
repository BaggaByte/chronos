import eventsJson from "@/data/events.json";
import reportJson from "@/data/report.json";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type ChronosEvent = {
  event_id: string;
  utc_timestamp: string;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  action: string;
  source_type: string;
  severity: Severity | string;
  attack_techniques: string[];
  correlation_group_id: string | null;
  offset_inferred: boolean;
  raw_ref: string;
};

export type CorrelationGroup = {
  group_id: string;
  keys: {
    src_ip: string;
    users: string;
    hosts: string;
    sessions: string;
  };
  event_count: number;
  techniques: string[];
  start: string;
  end: string;
  narrative: string;
};

export type Spike = {
  type: string;
  host: string;
  bin_start_utc: string;
  count: number;
  z_score: number;
  mean: number;
  severity: string;
};

export type Gap = {
  type: string;
  group_id: string;
  from_event: string;
  to_event: string;
  from_ts: string;
  to_ts: string;
  gap_seconds: number;
  threshold_seconds: number;
  hosts: string[];
  severity: string;
};

export type ManifestEntry = {
  source: string;
  sha256: string;
  events: number;
  parser: string;
};

export type ForensicReport = {
  manifest: ManifestEntry[];
  total_events: number;
  offset_inferred_count: number;
  technique_counts: Record<string, number>;
  correlation_groups: CorrelationGroup[];
  spikes: Spike[];
  gaps: Gap[];
  ground_truth_match: {
    attacker_ip_seen: boolean;
    compromised_user_seen: boolean;
  };
};

export const events = eventsJson as ChronosEvent[];
export const report = reportJson as ForensicReport;

export const primaryGroup = report.correlation_groups?.[0];

export const attackerEvents = events
  .filter((e) => e.correlation_group_id === primaryGroup?.group_id)
  .sort((a, b) => a.utc_timestamp.localeCompare(b.utc_timestamp));

const firstDateStr = attackerEvents[0]?.utc_timestamp
  ? attackerEvents[0].utc_timestamp.slice(0, 10).replace(/-/g, "")
  : "20250912";

export const CASE_ID = primaryGroup?.group_id
  ? `CASE-${firstDateStr}-${primaryGroup.group_id.toUpperCase()}`
  : "CASE-20250912-CORR-001";
export const CASE_TITLE = "Multi-Stage Attack & Exfiltration Timeline";
export const ATTACKER_IP = primaryGroup?.keys?.src_ip || "203.0.113.77";
export const COMPROMISED_USER = primaryGroup?.keys?.users || "j.mitchell";

export const dwellDurationSeconds =
  attackerEvents.length > 1
    ? Math.floor(
        (new Date(attackerEvents[attackerEvents.length - 1].utc_timestamp).getTime() -
          new Date(attackerEvents[0].utc_timestamp).getTime()) /
          1000,
      )
    : 0;

export const TECHNIQUE_META: Record<
  string,
  { name: string; tactic: string }
> = {
  T1566: { name: "Phishing", tactic: "Initial Access" },
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1003: { name: "OS Credential Dumping", tactic: "Credential Access" },
  T1021: { name: "Remote Services", tactic: "Lateral Movement" },
  T1078: { name: "Valid Accounts", tactic: "Defense Evasion" },
  T1560: { name: "Archive Collected Data", tactic: "Collection" },
  T1041: { name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  T1082: { name: "System Information Discovery", tactic: "Discovery" },
};

const BASE_STAGES = [
  {
    id: "access",
    label: "Initial Access",
    tactics: ["T1566", "T1190"],
  },
  {
    id: "dump",
    label: "Credential Dump",
    tactics: ["T1003"],
  },
  {
    id: "lateral",
    label: "Lateral Movement",
    tactics: ["T1021", "T1078"],
  },
  {
    id: "stage",
    label: "Staging",
    tactics: ["T1560"],
  },
  {
    id: "exfil",
    label: "Exfiltration",
    tactics: ["T1041", "T1082"],
  },
] as const;

export const STAGES = BASE_STAGES.map((stage) => {
  const stageEvents = attackerEvents.filter((e) =>
    e.attack_techniques?.some((t) => (stage.tactics as readonly string[]).includes(t)),
  );
  return {
    ...stage,
    start: stageEvents[0]?.utc_timestamp || "",
    end: stageEvents[stageEvents.length - 1]?.utc_timestamp || "",
  };
});

export const timelineStart =
  attackerEvents.length > 0
    ? new Date(attackerEvents[0].utc_timestamp).getTime() - 15 * 60 * 1000
    : new Date("2025-09-12T08:00:00Z").getTime();

export const timelineEnd =
  attackerEvents.length > 0
    ? new Date(attackerEvents[attackerEvents.length - 1].utc_timestamp).getTime() + 15 * 60 * 1000
    : new Date("2025-09-12T15:30:00Z").getTime();

export function formatUtc(iso: string, withDate = true) {
  const d = new Date(iso);
  const hh = d.toISOString().slice(11, 19);
  if (!withDate) return `${hh}Z`;
  return `${d.toISOString().slice(0, 10)} ${hh}Z`;
}

export function formatDuration(seconds: number) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h && m) return `${h}h ${m}m`;
  if (h) return `${h}h`;
  if (m) return `${m}m`;
  return `${seconds}s`;
}

export function unique<T>(arr: (T | null | undefined)[]): T[] {
  return [...new Set(arr.filter((x): x is T => x != null && x !== ""))];
}
