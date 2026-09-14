import { primaryGroup } from "@/lib/incident";

export function Narrative() {
  const lines = primaryGroup.narrative.split("\n");
  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <h2 className="text-sm font-medium">Attacker narrative</h2>
      <p className="mb-3 text-xs text-muted">
        {primaryGroup.event_count} correlated events across{" "}
        {primaryGroup.keys.hosts.split(",").length} hosts
      </p>
      <ol className="max-h-72 space-y-1.5 overflow-auto font-mono text-[11px] leading-relaxed text-muted">
        {lines.map((line, i) => (
          <li key={i} className="rounded-sm bg-elevated/60 px-2 py-1.5 text-fg/90">
            <span className="mr-2 text-subtle">{String(i + 1).padStart(2, "0")}</span>
            {line}
          </li>
        ))}
      </ol>
    </div>
  );
}
