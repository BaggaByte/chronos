import { useMemo, useState, useEffect } from "react";
import { Download, Search, Play, Pause, RotateCcw, FileSpreadsheet, FileText, Clock, ShieldAlert } from "lucide-react";
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
  ATTACKER_IP,
  COMPROMISED_USER,
  attackerEvents,
  events,
  primaryGroup,
  report,
  STAGES,
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
  const [isPlaying, setIsPlaying] = useState(false);

  const currentStep = useMemo(() => {
    const idx = attackerEvents.findIndex((e) => e.event_id === selected?.event_id);
    return idx >= 0 ? idx + 1 : 1;
  }, [selected]);

  useEffect(() => {
    if (!isPlaying) return;
    const timer = setInterval(() => {
      setSelected((prev) => {
        const currIdx = attackerEvents.findIndex((e) => e.event_id === prev?.event_id);
        const nextIdx = currIdx + 1;
        if (nextIdx >= attackerEvents.length) {
          setIsPlaying(false);
          return attackerEvents[0];
        }
        return attackerEvents[nextIdx];
      });
    }, 2000);
    return () => clearInterval(timer);
  }, [isPlaying]);

  const handlePrev = () => {
    const currIdx = attackerEvents.findIndex((e) => e.event_id === selected?.event_id);
    const prevIdx = currIdx > 0 ? currIdx - 1 : attackerEvents.length - 1;
    setSelected(attackerEvents[prevIdx]);
  };

  const handleNext = () => {
    const currIdx = attackerEvents.findIndex((e) => e.event_id === selected?.event_id);
    const nextIdx = (currIdx + 1) % attackerEvents.length;
    setSelected(attackerEvents[nextIdx]);
  };

  const exportCsv = () => {
    const headers = ["Event ID", "Timestamp (UTC)", "Host", "User", "Source IP", "Action", "Log Type", "Severity", "ATT&CK Techniques", "Offset Inferred"];
    const rows = (threadOnly ? attackerEvents : events).map((e) => [
      e.event_id,
      e.utc_timestamp,
      e.host || "",
      e.user || "",
      e.src_ip || "",
      `"${(e.action || "").replace(/"/g, '""')}"`,
      e.source_type,
      e.severity,
      `"${(e.attack_techniques || []).join("; ")}"`,
      e.offset_inferred ? "YES" : "NO",
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    download("chronos-forensic-events.csv", csvContent, "text/csv;charset=utf-8;");
  };

  const exportSummaryTxt = () => {
    const txt = `================================================================================
CHRONOS INCIDENT RESPONSE - FORENSIC EXECUTIVE SUMMARY
================================================================================
Case ID:            ${CASE_ID}
Title:              ${CASE_TITLE}
Primary Actor IP:   ${ATTACKER_IP}
Compromised User:   ${COMPROMISED_USER}
Attacker Events:    ${attackerEvents.length}
Total Events:       ${report.total_events}
Integrity Status:   VERIFIED (SHA-256 Pre-Ingest Hashes Checked)

INCIDENT NARRATIVE:
${primaryGroup.narrative}

KEY CORRELATED ATTACK STAGES:
${STAGES.map((s) => `[${s.label}] ${s.start} -> ${s.end} (${s.tactics.join(", ")})`).join("\n")}

ANOMALY DETECTION FINDINGS:
- Spikes: ${report.spikes.map((s) => `${s.host}: ${s.count} events (z=${s.z_score})`).join(", ") || "None"}
- Suspicious Gaps: ${report.gaps.map((g) => `${g.gap_seconds}s between ${g.from_event} -> ${g.to_event}`).join(", ") || "None"}

EVIDENTIARY HASHES (CHAIN OF CUSTODY):
${report.manifest.map((m) => `- ${m.source} [${m.sha256}] (${m.events} events)`).join("\n")}
================================================================================`;
    download("chronos-forensic-summary.txt", txt, "text/plain;charset=utf-8;");
  };

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
            <div className="mt-0.5 flex size-9 items-center justify-center rounded-md border border-border bg-elevated font-mono text-xs tracking-widest text-accent-fg">
              CR
            </div>
            <div>
              <div className="flex items-center gap-2">
                <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-subtle">
                  Chronos Forensics
                </p>
                <span className="flex items-center gap-1 rounded bg-danger/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-danger">
                  <span className="size-1.5 animate-pulse rounded-full bg-danger"></span>
                  Active Breach
                </span>
              </div>
              <h1 className="text-lg font-medium tracking-tight">{CASE_TITLE}</h1>
              <p className="font-mono text-xs text-muted">
                {CASE_ID} · {primaryGroup.group_id} · <span className="text-fg font-medium">Actor:</span> {ATTACKER_IP} · <span className="text-fg font-medium">Victim:</span> {COMPROMISED_USER}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-md border border-border bg-surface px-2.5 py-1 text-xs text-muted">
              <Clock className="size-3.5 text-accent-fg" />
              <span>Dwell: <strong className="text-fg">4h 13m</strong></span>
            </div>
            <Badge tone="high">exfiltration</Badge>
            <Badge tone="medium">offset inferred {report.offset_inferred_count}</Badge>
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                title="Download JSON forensic report"
                onClick={() =>
                  download(
                    "chronos-report.json",
                    JSON.stringify(report, null, 2),
                    "application/json",
                  )
                }
              >
                <Download className="size-3.5 mr-1" />
                JSON
              </Button>
              <Button
                variant="outline"
                size="sm"
                title="Download CSV event timeline"
                onClick={exportCsv}
              >
                <FileSpreadsheet className="size-3.5 mr-1" />
                CSV
              </Button>
              <Button
                variant="outline"
                size="sm"
                title="Download Executive Summary"
                onClick={exportSummaryTxt}
              >
                <FileText className="size-3.5 mr-1" />
                Summary
              </Button>
            </div>
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1400px] gap-1 overflow-x-auto px-4 pb-3 sm:px-6">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              type="button"
              onClick={() => setView(v.id)}
              className={cn(
                "h-10 shrink-0 rounded-md px-4 text-sm transition-colors duration-150 font-medium",
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

        {/* Live Attack Playback Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface p-3 shadow-panel">
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 font-mono text-xs font-semibold text-accent-fg uppercase tracking-wider">
              <ShieldAlert className="size-4 text-danger" />
              Incident Replay:
            </span>
            <span className="rounded bg-elevated px-2 py-0.5 font-mono text-xs text-fg border border-border">
              Step {currentStep} / {attackerEvents.length}
            </span>
            <span className="text-xs text-muted truncate max-w-[320px]">
              {selected?.action} ({selected?.host})
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handlePrev}
              disabled={isPlaying}
              title="Step to previous event"
            >
              ⏮ Prev
            </Button>
            <Button
              variant={isPlaying ? "primary" : "outline"}
              size="sm"
              onClick={() => setIsPlaying(!isPlaying)}
              className={cn("gap-1.5", isPlaying && "bg-danger text-white hover:bg-danger/90")}
            >
              {isPlaying ? (
                <>
                  <Pause className="size-3.5" /> Pause
                </>
              ) : (
                <>
                  <Play className="size-3.5" /> Replay Incident
                </>
              )}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleNext}
              disabled={isPlaying}
              title="Step to next event"
            >
              Next ⏭
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setIsPlaying(false);
                setSelected(attackerEvents[0]);
              }}
              title="Reset to beginning"
            >
              <RotateCcw className="size-3.5" />
            </Button>
          </div>
        </div>

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
