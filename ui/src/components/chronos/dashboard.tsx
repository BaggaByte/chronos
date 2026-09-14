import { useMemo, useState } from "react";
import { Download, Search } from "lucide-react";
import { Anomalies } from "@/components/chronos/anomalies";
import { AttackMatrix } from "@/components/chronos/attack-matrix";
import { AttackTimeline } from "@/components/chronos/attack-timeline";
import { Custody } from "@/components/chronos/custody";
import { EventTable } from "@/components/chronos/event-table";
import { HostGraph } from "@/components/chronos/host-graph";
import { Inspector } from "@/components/chronos/inspector";
import { KillChain } from "@/components/chronos/kill-chain";
import { Kpis } from "@/components/chronos/kpis";
import { Narrative } from "@/components/chronos/narrative";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  CASE_ID,
  CASE_TITLE,
  attackerEvents,
  events,
  primaryGroup,
  report,
  type ChronosEvent,
} from "@/lib/incident";
import { cn } from "@/lib/utils";

const VIEWS = [
  { id: "overview", label: "Overview" },
  { id: "timeline", label: "Timeline" },
  { id: "attack", label: "ATT&CK" },
  { id: "events", label: "Events" },
  { id: "custody", label: "Custody" },
] as const;

type View = (typeof VIEWS)[number]["id"];

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function Dashboard() {
  const [view, setView] = useState<View>("overview");
  const [query, setQuery] = useState("");
  const [threadOnly, setThreadOnly] = useState(true);
  const [selected, setSelected] = useState<ChronosEvent | null>(
    attackerEvents[0] ?? null,
  );

  const filtered = useMemo(() => {
    const base = threadOnly ? attackerEvents : events;
    const q = query.trim().toLowerCase();
    if (!q) return base;
    return base.filter((e) =>
      [e.action, e.host, e.user, e.src_ip, e.source_type, ...e.attack_techniques]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [query, threadOnly]);

  return (
    <div className="min-h-screen bg-bg text-fg">
      <header className="sticky top-0 z-20 border-b border-border bg-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-[1400px] flex-col gap-3 px-4 py-3 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex size-9 items-center justify-center rounded-md border border-border bg-elevated font-mono text-xs tracking-widest">
              CR
            </div>
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-subtle">
                Chronos forensics
              </p>
              <h1 className="text-lg font-medium tracking-tight">{CASE_TITLE}</h1>
              <p className="font-mono text-xs text-muted">
                {CASE_ID} · {primaryGroup.group_id}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="high">exfiltration</Badge>
            <Badge tone="medium">offset inferred {report.offset_inferred_count}</Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                download(
                  "chronos-report.json",
                  JSON.stringify(report, null, 2),
                  "application/json",
                )
              }
            >
              <Download className="size-3.5" />
              Export
            </Button>
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1400px] gap-1 overflow-x-auto px-4 pb-3 sm:px-6">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              type="button"
              onClick={() => setView(v.id)}
              className={cn(
                "h-10 shrink-0 rounded-md px-4 text-sm transition-colors duration-150",
                view === v.id
                  ? "bg-accent text-accent-fg"
                  : "text-muted hover:bg-elevated hover:text-fg",
              )}
            >
              {v.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-[1400px] space-y-4 px-4 py-4 sm:px-6 sm:py-6">
        <Kpis />

        {view === "overview" && (
          <div className="space-y-4">
            <KillChain />
            <AttackTimeline selectedId={selected?.event_id} onSelect={setSelected} />
            <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
              <Narrative />
              <HostGraph />
            </div>
            <Anomalies />
          </div>
        )}

        {view === "timeline" && (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(260px,0.9fr)]">
            <div className="space-y-4">
              <AttackTimeline selectedId={selected?.event_id} onSelect={setSelected} />
              <EventTable
                rows={attackerEvents}
                selectedId={selected?.event_id}
                onSelect={setSelected}
              />
            </div>
            <Inspector event={selected} onClose={() => setSelected(null)} />
          </div>
        )}

        {view === "attack" && (
          <div className="grid gap-4 lg:grid-cols-[1fr_1.2fr]">
            <AttackMatrix />
            <div className="space-y-4">
              <KillChain />
              <Anomalies />
            </div>
          </div>
        )}

        {view === "events" && (
          <div className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
              <label className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter host, IP, user, action, technique"
                  className="h-11 w-full rounded-md border border-border bg-surface pl-10 pr-3 text-sm text-fg outline-none ring-accent/30 placeholder:text-subtle focus:ring-2"
                />
              </label>
              <Button
                variant={threadOnly ? "primary" : "outline"}
                size="sm"
                onClick={() => setThreadOnly((v) => !v)}
              >
                {threadOnly ? "Attacker thread" : "All events"}
              </Button>
            </div>
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(260px,0.9fr)]">
              <EventTable
                rows={filtered}
                selectedId={selected?.event_id}
                onSelect={setSelected}
              />
              <Inspector event={selected} onClose={() => setSelected(null)} />
            </div>
          </div>
        )}

        {view === "custody" && <Custody />}
      </main>
    </div>
  );
}
