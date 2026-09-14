import { Badge } from "@/components/ui/badge";
import { formatDuration, formatUtc, report } from "@/lib/incident";

export function Anomalies() {
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <section className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
        <h2 className="text-sm font-medium">Execution spikes</h2>
        <p className="mb-3 text-xs text-muted">Rolling z-score on 5-minute bins</p>
        <ul className="space-y-2">
          {report.spikes.map((s) => (
            <li
              key={s.host + s.bin_start_utc}
              className="flex items-center justify-between gap-3 rounded-md border border-border bg-elevated px-3 py-2"
            >
              <div className="min-w-0">
                <p className="truncate font-mono text-xs text-fg">{s.host}</p>
                <p className="text-[11px] text-muted">
                  {formatUtc(s.bin_start_utc, false)} · count {s.count} · z {s.z_score}
                </p>
              </div>
              <Badge tone={s.severity}>{s.severity}</Badge>
            </li>
          ))}
        </ul>
      </section>
      <section className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
        <h2 className="text-sm font-medium">Dwell-time gaps</h2>
        <p className="mb-3 text-xs text-muted">Adaptive threshold between stages</p>
        <ul className="space-y-2">
          {report.gaps.map((g) => (
            <li
              key={g.from_event + g.to_event}
              className="flex items-center justify-between gap-3 rounded-md border border-border bg-elevated px-3 py-2"
            >
              <div className="min-w-0">
                <p className="truncate font-mono text-xs text-fg">
                  {g.hosts.join(" → ")}
                </p>
                <p className="text-[11px] text-muted">
                  {formatDuration(g.gap_seconds)} dwell · thresh{" "}
                  {formatDuration(g.threshold_seconds)}
                </p>
              </div>
              <Badge tone={g.severity}>{g.severity}</Badge>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
