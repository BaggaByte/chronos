import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatUtc, TECHNIQUE_META, type ChronosEvent } from "@/lib/incident";
import { X } from "lucide-react";

export function Inspector({
  event,
  onClose,
}: {
  event: ChronosEvent | null;
  onClose: () => void;
}) {
  if (!event) return null;
  const fields: [string, string][] = [
    ["Event ID", event.event_id],
    ["UTC", formatUtc(event.utc_timestamp)],
    ["Source", event.source_type],
    ["Host", event.host ?? "—"],
    ["User", event.user ?? "—"],
    ["Src IP", event.src_ip ?? "—"],
    ["Dst IP", event.dst_ip ?? "—"],
    ["Action", event.action],
    ["Ref", event.raw_ref],
    ["Offset inferred", event.offset_inferred ? "yes" : "no"],
    ["Group", event.correlation_group_id ?? "ungrouped"],
  ];
  return (
    <aside className="flex h-full flex-col rounded-lg border border-border bg-surface shadow-panel">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <p className="text-xs uppercase tracking-wider text-subtle">Event inspector</p>
          <h3 className="text-sm font-medium">{event.action}</h3>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close inspector">
          <X className="size-4" />
        </Button>
      </div>
      <div className="flex flex-wrap gap-1.5 px-4 pt-3">
        <Badge tone={event.severity}>{event.severity}</Badge>
        {event.attack_techniques.map((t) => (
          <Badge key={t} tone="accent">
            {t} {TECHNIQUE_META[t]?.name ?? ""}
          </Badge>
        ))}
      </div>
      <dl className="flex-1 space-y-2 overflow-auto p-4 text-sm">
        {fields.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[110px_1fr] gap-2">
            <dt className="text-subtle">{k}</dt>
            <dd className="font-mono text-xs break-all text-fg">{v}</dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}
