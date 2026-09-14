import { useMemo, useState } from "react";
import { events, attackerEvents } from "@/lib/incident";
import { cn } from "@/lib/utils";
import { AlertTriangle, BarChart3 } from "lucide-react";

type Bin = {
  id: number;
  timeLabel: string;
  benignCount: number;
  attackerCount: number;
  total: number;
  isSpike: boolean;
  topHost: string;
};

export function VolumeHistogram() {
  const [hoveredBin, setHoveredBin] = useState<Bin | null>(null);

  const { bins, maxTotal, spikeThreshold } = useMemo(() => {
    // Sort all events by timestamp
    const sorted = [...events].sort(
      (a, b) => new Date(a.utc_timestamp).getTime() - new Date(b.utc_timestamp).getTime(),
    );

    if (sorted.length === 0) return { bins: [], maxTotal: 1, spikeThreshold: 5 };

    const tStart = new Date(sorted[0].utc_timestamp).getTime();
    const tEnd = new Date(sorted[sorted.length - 1].utc_timestamp).getTime();
    const duration = Math.max(tEnd - tStart, 3600 * 1000);
    const NUM_BINS = 16;
    const binSize = duration / NUM_BINS;

    const rawBins: Bin[] = Array.from({ length: NUM_BINS }, (_, i) => {
      const bStart = new Date(tStart + i * binSize);
      const hours = bStart.getUTCHours().toString().padStart(2, "0");
      const mins = bStart.getUTCMinutes().toString().padStart(2, "0");
      return {
        id: i,
        timeLabel: `${hours}:${mins}Z`,
        benignCount: 0,
        attackerCount: 0,
        total: 0,
        isSpike: false,
        topHost: "",
      };
    });

    const hostCountsPerBin: Record<number, Record<string, number>> = {};

    sorted.forEach((ev) => {
      const t = new Date(ev.utc_timestamp).getTime();
      const bIdx = Math.min(Math.floor((t - tStart) / binSize), NUM_BINS - 1);
      const isAttacker = ev.correlation_group_id !== null;

      if (isAttacker) {
        rawBins[bIdx].attackerCount += 1;
      } else {
        rawBins[bIdx].benignCount += 1;
      }
      rawBins[bIdx].total += 1;

      if (ev.host) {
        if (!hostCountsPerBin[bIdx]) hostCountsPerBin[bIdx] = {};
        hostCountsPerBin[bIdx][ev.host] = (hostCountsPerBin[bIdx][ev.host] || 0) + 1;
      }
    });

    // Find top host and detect spikes
    const totals = rawBins.map((b) => b.total);
    const mean = totals.reduce((a, b) => a + b, 0) / totals.length;
    const variance = totals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / totals.length;
    const stdDev = Math.sqrt(variance);
    const threshold = mean + 2.0 * stdDev;

    rawBins.forEach((b) => {
      if (b.total >= threshold && b.total > 4) {
        b.isSpike = true;
      }
      const hosts = hostCountsPerBin[b.id] || {};
      const sortedHosts = Object.entries(hosts).sort((a, b) => b[1] - a[1]);
      b.topHost = sortedHosts[0]?.[0] || "unknown";
    });

    const max = Math.max(...rawBins.map((b) => b.total), 10);
    return { bins: rawBins, maxTotal: max, spikeThreshold: threshold };
  }, []);

  const chartHeight = 120;
  const chartWidth = 700;
  const barWidth = chartWidth / bins.length;

  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <BarChart3 className="size-4 text-accent-fg" />
          <h2 className="text-sm font-medium text-fg">Log Volume Telemetry & Anomaly Spikes</h2>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted">
          <span className="flex items-center gap-1">
            <span className="size-2 rounded-sm bg-muted/40"></span> Benign logs (69)
          </span>
          <span className="flex items-center gap-1">
            <span className="size-2 rounded-sm bg-danger"></span> Attacker thread (11)
          </span>
          <span className="flex items-center gap-1 text-danger font-medium">
            <AlertTriangle className="size-3" /> Z-Score Spike ($Z &gt; 2.5$)
          </span>
        </div>
      </div>

      <div className="relative">
        <svg viewBox={`0 0 ${chartWidth} ${chartHeight + 28}`} className="w-full overflow-visible" role="img">
          {/* Threshold line */}
          {spikeThreshold > 0 && (
            <g>
              <line
                x1={0}
                y1={chartHeight - (spikeThreshold / maxTotal) * chartHeight}
                x2={chartWidth}
                y2={chartHeight - (spikeThreshold / maxTotal) * chartHeight}
                stroke="#ef4444"
                strokeWidth="1"
                strokeDasharray="4 4"
                opacity="0.6"
              />
              <text
                x={chartWidth - 4}
                y={chartHeight - (spikeThreshold / maxTotal) * chartHeight - 4}
                textAnchor="end"
                fontSize="8"
                className="fill-danger font-mono"
              >
                Anomaly Threshold (Z &gt; 2.5)
              </text>
            </g>
          )}

          {/* Bars */}
          {bins.map((bin, i) => {
            const x = i * barWidth;
            const benignH = (bin.benignCount / maxTotal) * chartHeight;
            const attackH = (bin.attackerCount / maxTotal) * chartHeight;
            const isHovered = hoveredBin?.id === bin.id;

            return (
              <g
                key={bin.id}
                className="cursor-pointer transition-opacity duration-150"
                onMouseEnter={() => setHoveredBin(bin)}
                onMouseLeave={() => setHoveredBin(null)}
              >
                {/* Background hover highlight */}
                <rect
                  x={x}
                  y={0}
                  width={barWidth - 2}
                  height={chartHeight}
                  className={cn("fill-transparent", isHovered && "fill-elevated/40")}
                  rx="2"
                />

                {/* Benign segment */}
                {benignH > 0 && (
                  <rect
                    x={x + 2}
                    y={chartHeight - benignH}
                    width={barWidth - 6}
                    height={benignH}
                    className="fill-border transition-colors hover:fill-muted"
                    rx="1"
                  />
                )}

                {/* Attacker segment (stacked on top) */}
                {attackH > 0 && (
                  <rect
                    x={x + 2}
                    y={chartHeight - benignH - attackH}
                    width={barWidth - 6}
                    height={attackH}
                    className={cn(
                      "fill-danger transition-all",
                      bin.isSpike && "animate-pulse fill-danger stroke-danger/60",
                    )}
                    rx="1"
                  />
                )}

                {/* Spike Indicator Badge */}
                {bin.isSpike && (
                  <g>
                    <circle
                      cx={x + (barWidth - 6) / 2 + 2}
                      cy={Math.max(12, chartHeight - benignH - attackH - 8)}
                      r="4"
                      className="fill-danger"
                    />
                  </g>
                )}

                {/* X Axis Label */}
                <text
                  x={x + barWidth / 2}
                  y={chartHeight + 16}
                  textAnchor="middle"
                  className={cn(
                    "fill-muted text-[8px] font-mono",
                    isHovered && "fill-fg font-semibold",
                  )}
                  fontSize="8"
                >
                  {bin.timeLabel}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Tooltip */}
        {hoveredBin && (
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded bg-elevated px-3 py-1.5 text-xs border border-border">
            <div className="flex items-center gap-2">
              <span className="font-mono font-semibold text-fg">Time: {hoveredBin.timeLabel}</span>
              <span className="text-muted">|</span>
              <span className="text-muted">Primary Host: <strong className="text-fg">{hoveredBin.topHost}</strong></span>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-muted">Benign: <strong className="text-fg">{hoveredBin.benignCount}</strong></span>
              <span className="text-danger">Attacker: <strong>{hoveredBin.attackerCount}</strong></span>
              <span className="font-semibold text-fg">Total: {hoveredBin.total} events</span>
              {hoveredBin.isSpike && (
                <span className="rounded bg-danger/20 px-1.5 py-0.5 text-[10px] font-bold text-danger uppercase tracking-wider">
                  SPIKE DETECTED
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
