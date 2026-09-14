import { Badge } from "@/components/ui/badge";
import { report } from "@/lib/incident";

export function Custody() {
  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">Chain of custody</h2>
          <p className="text-xs text-muted">SHA-256 of raw sources before parse</p>
        </div>
        <Badge tone="low">verified</Badge>
      </div>
      <ul className="divide-y divide-border">
        {report.manifest.map((m) => (
          <li key={m.source} className="flex flex-col gap-1 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="font-mono text-sm text-fg">{m.source}</p>
              <p className="font-mono text-[11px] break-all text-subtle">{m.sha256}</p>
            </div>
            <p className="font-mono text-xs tabular-nums text-muted">
              {m.events} events · parser {m.parser}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
