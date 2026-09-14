import { Badge } from "@/components/ui/badge";
import { formatUtc, type ChronosEvent } from "@/lib/incident";
import { cn } from "@/lib/utils";

export function EventTable({
  rows,
  selectedId,
  onSelect,
}: {
  rows: ChronosEvent[];
  selectedId?: string | null;
  onSelect: (event: ChronosEvent) => void;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-surface shadow-panel">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="border-b border-border bg-elevated text-[10px] uppercase tracking-wider text-subtle">
            <tr>
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Host</th>
              <th className="px-3 py-2 font-medium">Actor</th>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Techniques</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((ev) => {
              const selected = selectedId === ev.event_id;
              return (
                <tr
                  key={ev.event_id}
                  className={cn(
                    "cursor-pointer border-b border-border/70 transition-colors duration-150 hover:bg-elevated",
                    selected && "bg-elevated",
                  )}
                  onClick={() => onSelect(ev)}
                >
                  <td className="px-3 py-2 font-mono text-xs tabular-nums text-muted">
                    {formatUtc(ev.utc_timestamp, false)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{ev.host ?? "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs text-muted">
                    {ev.user ?? ev.src_ip ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-fg">{ev.action}</td>
                  <td className="px-3 py-2">
                    <Badge tone={ev.severity}>{ev.severity}</Badge>
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px] text-muted">
                    {ev.attack_techniques.join(" ") || "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
