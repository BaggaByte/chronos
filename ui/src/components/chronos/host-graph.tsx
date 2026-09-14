import { ATTACKER_IP, attackerEvents, unique } from "@/lib/incident";

const HOSTS = unique(attackerEvents.map((e) => e.host));

export function HostGraph() {
  const width = 520;
  const height = 260;
  const cx = width / 2;
  const cy = height / 2 + 8;
  const r = 88;
  const nodes = HOSTS.map((host, i) => {
    const a = (Math.PI * 2 * i) / HOSTS.length - Math.PI / 2;
    return { host, x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r };
  });

  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <h2 className="text-sm font-medium text-fg">Cross-host correlation</h2>
      <p className="mb-2 text-xs text-muted">
        Joined on {ATTACKER_IP} + j.mitchell
      </p>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img">
        {nodes.map((n) => (
          <line
            key={n.host}
            x1={cx}
            y1={cy}
            x2={n.x}
            y2={n.y}
            stroke="currentColor"
            className="text-border"
          />
        ))}
        <circle cx={cx} cy={cy} r={22} className="fill-elevated stroke-accent/40" strokeWidth="1" />
        <text
          x={cx}
          y={cy + 4}
          textAnchor="middle"
          className="fill-fg"
          fontSize="9"
          fontFamily="IBM Plex Mono, monospace"
        >
          actor
        </text>
        {nodes.map((n) => (
          <g key={n.host}>
            <circle cx={n.x} cy={n.y} r={16} className="fill-elevated stroke-border" />
            <text
              x={n.x}
              y={n.y + 32}
              textAnchor="middle"
              className="fill-muted"
              fontSize="10"
              fontFamily="IBM Plex Mono, monospace"
            >
              {n.host}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
