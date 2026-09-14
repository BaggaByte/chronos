import { useMemo, useState, useRef, useEffect } from "react";
import {
  attackerEvents,
  formatUtc,
  report,
  STAGES,
  timelineEnd,
  timelineStart,
  type ChronosEvent,
} from "@/lib/incident";
import { cn } from "@/lib/utils";

function xOf(iso: string, width: number) {
  const t = new Date(iso).getTime();
  return ((t - timelineStart) / (timelineEnd - timelineStart)) * width;
}

const WIDTH = 1000;
const HEIGHT = 200;
const PAD = 36;

export function AttackTimeline({
  selectedId,
  onSelect,
}: {
  selectedId?: string | null;
  onSelect: (event: ChronosEvent) => void;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [panX, setPanX] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const [startX, setStartX] = useState(0);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = 1.1;
      const direction = e.deltaY > 0 ? -1 : 1;
      let newZoom = direction > 0 ? zoom * zoomFactor : zoom / zoomFactor;
      newZoom = Math.max(1, Math.min(newZoom, 15));
      
      const svgRect = svg.getBoundingClientRect();
      const mouseX = e.clientX - svgRect.left;
      const svgX = panX + (mouseX / svgRect.width) * (WIDTH / zoom);
      
      let newPanX = svgX - (mouseX / svgRect.width) * (WIDTH / newZoom);
      newPanX = Math.max(0, Math.min(newPanX, WIDTH - WIDTH / newZoom));
      
      setZoom(newZoom);
      setPanX(newPanX);
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, [zoom, panX]);

  const handlePointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    setIsDragging(true);
    setStartX(e.clientX);
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!isDragging) return;
    const dx = e.clientX - startX;
    setStartX(e.clientX);
    const svgRect = e.currentTarget.getBoundingClientRect();
    const scale = (WIDTH / zoom) / svgRect.width;
    let newPanX = panX - dx * scale;
    newPanX = Math.max(0, Math.min(newPanX, WIDTH - WIDTH / zoom));
    setPanX(newPanX);
  };

  const handlePointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    setIsDragging(false);
    e.currentTarget.releasePointerCapture(e.pointerId);
  };

  const ticks = useMemo(() => {
    const hours = [8, 9, 10, 11, 12, 13, 14, 15];
    return hours.map((h) => {
      const iso = `2025-09-12T${String(h).padStart(2, "0")}:00:00Z`;
      return { label: `${h}:00Z`, x: xOf(iso, WIDTH - PAD * 2) + PAD };
    });
  }, []);

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
        <div>
          <h2 className="text-sm font-medium text-fg">Reconstructed timeline</h2>
          <p className="text-xs text-muted">
            Attacker thread · hashed bars are dwell gaps · dashed lines are spikes
          </p>
        </div>
        <ul className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-subtle">
          {STAGES.map((s, i) => (
            <li key={s.id}>
              {String(i + 1).padStart(2, "0")} {s.label}
            </li>
          ))}
        </ul>
      </div>
      <svg
        ref={svgRef}
        viewBox={`${panX} 0 ${WIDTH / zoom} ${HEIGHT}`}
        className="h-auto w-full min-w-[640px] touch-none cursor-grab active:cursor-grabbing"
        role="img"
        aria-label="Attacker timeline"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerUp}
      >
        {STAGES.map((stage, i) => {
          const x1 = xOf(stage.start, WIDTH - PAD * 2) + PAD;
          const x2 = Math.max(xOf(stage.end, WIDTH - PAD * 2) + PAD, x1 + 8);
          return (
            <g key={stage.id}>
              <rect
                x={x1}
                y={52}
                width={x2 - x1}
                height={56}
                rx={3}
                className="fill-elevated"
              />
              <text
                x={x1}
                y={46}
                className="fill-subtle"
                fontSize="10"
                fontFamily="IBM Plex Mono, monospace"
              >
                {String(i + 1).padStart(2, "0")}
              </text>
            </g>
          );
        })}
        {report.gaps.map((gap) => {
          const x1 = xOf(gap.from_ts, WIDTH - PAD * 2) + PAD;
          const x2 = xOf(gap.to_ts, WIDTH - PAD * 2) + PAD;
          return (
            <rect
              key={gap.from_event + gap.to_event}
              x={x1}
              y={122}
              width={Math.max(x2 - x1, 2)}
              height={6}
              className="fill-warn/30"
            />
          );
        })}
        <line
          x1={PAD}
          x2={WIDTH - PAD}
          y1={148}
          y2={148}
          className="stroke-border"
        />
        {ticks.map((t) => (
          <g key={t.label}>
            <line x1={t.x} x2={t.x} y1={144} y2={152} className="stroke-muted" />
            <text
              x={t.x}
              y={168}
              textAnchor="middle"
              className="fill-subtle"
              fontSize="10"
              fontFamily="IBM Plex Mono, monospace"
            >
              {t.label}
            </text>
          </g>
        ))}
        {report.spikes.map((spike) => {
          const x = xOf(spike.bin_start_utc, WIDTH - PAD * 2) + PAD;
          return (
            <line
              key={spike.host + spike.bin_start_utc}
              x1={x}
              x2={x}
              y1={28}
              y2={142}
              className="stroke-warn/45"
              strokeDasharray="3 4"
            />
          );
        })}
        {attackerEvents.map((ev, i) => {
          const x = xOf(ev.utc_timestamp, WIDTH - PAD * 2) + PAD;
          const selected = selectedId === ev.event_id || hover === ev.event_id;
          const tone =
            ev.severity === "high"
              ? "text-danger"
              : ev.severity === "medium"
                ? "text-warn"
                : "text-info";
          return (
            <g
              key={ev.event_id}
              className="cursor-pointer"
              onMouseEnter={() => setHover(ev.event_id)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onSelect(ev)}
            >
              {/* Radar targeting pulse when selected (pure SVG animation to prevent coordinate drift) */}
              {selected && (
                <>
                  <circle
                    cx={x}
                    cy={80}
                    r={6}
                    className={cn(tone, "pointer-events-none")}
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  >
                    <animate attributeName="r" values="6;22" dur="1.3s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.85;0" dur="1.3s" repeatCount="indefinite" />
                  </circle>
                  <circle
                    cx={x}
                    cy={80}
                    r={10}
                    className={cn(tone, "opacity-25 pointer-events-none")}
                    fill="currentColor"
                  />
                </>
              )}
              <circle
                cx={x}
                cy={80}
                r={selected ? 7 : 4.5}
                className={cn(tone, "transition-all duration-200")}
                fill="currentColor"
              />
              {selected ? (
                <text
                  x={Math.min(Math.max(x, 130), WIDTH - 130)}
                  y={22}
                  textAnchor="middle"
                  className="fill-fg font-medium"
                  fontSize="11"
                  fontFamily="IBM Plex Sans, sans-serif"
                >
                  #{i + 1} · {formatUtc(ev.utc_timestamp, false)} · {ev.action}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
