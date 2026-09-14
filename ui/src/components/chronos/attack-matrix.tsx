import { report, TECHNIQUE_META } from "@/lib/incident";
import { Badge } from "@/components/ui/badge";

export function AttackMatrix() {
  const entries = Object.entries(report.technique_counts).sort(
    (a, b) => b[1] - a[1],
  );
  const max = Math.max(...entries.map(([, n]) => n));
  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <h2 className="text-sm font-medium text-fg">ATT&CK techniques</h2>
      <p className="mb-4 text-xs text-muted">Technique-level tags, not tactic labels</p>
      <ul className="space-y-3">
        {entries.map(([id, count]) => {
          const meta = TECHNIQUE_META[id];
          const pct = Math.max(12, (count / max) * 100);
          return (
            <li key={id}>
              <div className="mb-1 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm text-fg">
                    <span className="font-mono text-xs text-muted">{id}</span>{" "}
                    {meta?.name ?? id}
                  </p>
                  <p className="text-[11px] text-subtle">{meta?.tactic}</p>
                </div>
                <Badge tone="default">{count}</Badge>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-elevated">
                <div
                  className="h-full rounded-full bg-accent/70"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
