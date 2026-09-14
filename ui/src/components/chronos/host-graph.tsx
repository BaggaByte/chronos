import { useState } from "react";
import { ATTACKER_IP, attackerEvents, type ChronosEvent } from "@/lib/incident";
import { cn } from "@/lib/utils";
import { Network } from "lucide-react";

type HostNode = {
  id: string;
  label: string;
  role: string;
  tier: string;
  eventsCount: number;
  techniques: string[];
  x: number;
  y: number;
  status: "compromised" | "attacker" | "exfiltration";
};

export function HostGraph({ activeEvent }: { activeEvent?: ChronosEvent | null } = {}) {
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  const width = 560;
  const height = 240;

  const hostEvents = (hostName: string) =>
    attackerEvents.filter(
      (e) =>
        e.host === hostName ||
        (hostName === "s3.amazonaws.com" && Boolean(e.host?.includes("amazonaws.com"))),
    );

  const hostTechniques = (hostName: string) => {
    const s = new Set<string>();
    hostEvents(hostName).forEach((e) => e.attack_techniques?.forEach((t) => s.add(t)));
    return Array.from(s);
  };

  const allTechniques = Array.from(
    new Set(attackerEvents.flatMap((e) => e.attack_techniques || [])),
  );

  const rawHosts = Array.from(
    new Set(
      attackerEvents
        .map((e) => {
          if (!e.host) return null;
          if (e.host.includes("amazonaws.com") || e.action?.toLowerCase().includes("s3")) {
            return "s3.amazonaws.com";
          }
          if (e.host === "fw-edge-01") return null;
          return e.host;
        })
        .filter((h): h is string => Boolean(h)),
    ),
  );

  const distinctHosts =
    rawHosts.length > 0
      ? rawHosts
      : ["web-portal-01", "WIN-ENG-07", "lin-db-03", "s3.amazonaws.com"];

  function getHostMeta(host: string) {
    const h = host.toLowerCase();
    if (h.includes("s3") || h.includes("aws") || h.includes("cloud")) {
      return {
        label: host === "s3.amazonaws.com" ? "s3-vault" : host,
        role: "AWS S3 Bucket",
        tier: "Cloud Storage",
        status: "exfiltration" as const,
      };
    }
    if (h.includes("db") || h.includes("sql") || h.includes("data")) {
      return {
        label: host,
        role: "Core DB Server",
        tier: "Secure Zone",
        status: "compromised" as const,
      };
    }
    if (h.includes("eng") || h.includes("win") || h.includes("pc") || h.includes("work")) {
      return {
        label: host,
        role: "Engineer Workstation",
        tier: "Internal LAN",
        status: "compromised" as const,
      };
    }
    if (h.includes("web") || h.includes("portal") || h.includes("dmz") || h.includes("proxy") || h.includes("nginx")) {
      return {
        label: host,
        role: "DMZ Web App",
        tier: "Perimeter",
        status: "compromised" as const,
      };
    }
    return {
      label: host,
      role: "Internal Host",
      tier: "Internal Network",
      status: "compromised" as const,
    };
  }

  // Topological breach flow coordinates
  const nodes: HostNode[] = [
    {
      id: "actor",
      label: ATTACKER_IP,
      role: "Threat Actor",
      tier: "Internet Edge",
      eventsCount: attackerEvents.length,
      techniques: allTechniques,
      x: 55,
      y: 120,
      status: "attacker",
    },
    ...distinctHosts.map((hostName, i) => {
      const meta = getHostMeta(hostName);
      const x = 55 + ((i + 1) / (distinctHosts.length + 0.35)) * (width - 85);
      const y = i % 2 === 0 ? 65 : 155;
      return {
        id: hostName,
        label: meta.label,
        role: meta.role,
        tier: meta.tier,
        eventsCount: hostEvents(hostName).length,
        techniques: hostTechniques(hostName),
        x: Math.round(x),
        y,
        status: meta.status,
      };
    }),
  ];

  // Dynamically constructed hop connections
  const edges = nodes.slice(0, -1).map((node, i) => {
    const nextNode = nodes[i + 1];
    const label =
      i === 0
        ? "1. Initial Access"
        : i === nodes.length - 2
          ? `${i + 1}. Exfiltration`
          : `${i + 1}. Lateral Pivot`;
    return { from: node, to: nextNode, label };
  });

  const currentEventHost = activeEvent?.host;
  const isActorEvent =
    activeEvent?.src_ip === ATTACKER_IP &&
    (!currentEventHost ||
      activeEvent?.action?.toLowerCase().includes("recon") ||
      activeEvent?.action?.toLowerCase().includes("scan"));
  const isS3Event =
    currentEventHost === "s3.amazonaws.com" ||
    currentEventHost === "sts.amazonaws.com" ||
    Boolean(currentEventHost?.includes("amazonaws.com")) ||
    Boolean(activeEvent?.action?.toLowerCase().includes("s3")) ||
    Boolean(activeEvent?.action?.toLowerCase().includes("exfil"));
  const isFirewallEdge = currentEventHost === "fw-edge-01";

  const telemetryHostId = isActorEvent
    ? "actor"
    : isS3Event
      ? "s3.amazonaws.com"
      : isFirewallEdge
        ? distinctHosts[0]
        : currentEventHost || null;

  const activeNode =
    nodes.find((n) => n.id === (selectedHost || telemetryHostId)) || null;

  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-panel sm:p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="size-4 text-accent-fg" />
          <h2 className="text-sm font-medium text-fg">Topological Lateral Movement</h2>
        </div>
        <span className="font-mono text-[10px] text-muted uppercase tracking-wider">
          {nodes.length - 1}-Hop Pivot Chain
        </span>
      </div>
      <p className="mb-2 text-xs text-muted">
        Adversary path across perimeter, internal LAN, and cloud infrastructure
      </p>

      <div className="relative">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full overflow-visible" role="img">
          <defs>
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="6"
              refX="8"
              refY="3"
              orient="auto"
              className="fill-danger"
            >
              <polygon points="0 0, 8 3, 0 6" />
            </marker>
          </defs>

          {/* Connection paths */}
          {edges.map((e, i) => {
            // Cubic Bezier curve
            const dx = e.to.x - e.from.x;
            const dy = e.to.y - e.from.y;
            const cx1 = e.from.x + dx * 0.4;
            const cy1 = e.from.y;
            const cx2 = e.from.x + dx * 0.6;
            const cy2 = e.to.y;
            const pathD = `M ${e.from.x} ${e.from.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${e.to.x} ${e.to.y}`;

            return (
              <g key={i}>
                <path
                  d={pathD}
                  fill="none"
                  stroke="currentColor"
                  className="text-danger/40 animate-flow transition-colors hover:text-danger"
                  strokeWidth="2"
                  strokeDasharray="5 3"
                />
                <circle r="3" className="fill-danger animate-pulse">
                  <animateMotion path={pathD} dur={`${3 + i * 0.5}s`} repeatCount="indefinite" />
                </circle>
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => {
            const isHovered = selectedHost === n.id;
            const isTelemetryActive = telemetryHostId === n.id;
            const isFocused = isHovered || isTelemetryActive;
            const isAttacker = n.status === "attacker";
            const isExfil = n.status === "exfiltration";

            return (
              <g
                key={n.id}
                className="cursor-pointer"
                onMouseEnter={() => setSelectedHost(n.id)}
                onMouseLeave={() => setSelectedHost(null)}
              >
                {/* Active telemetry radar ping (pure SVG animation to prevent coordinate drift) */}
                {isTelemetryActive && (
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={18}
                    className="stroke-danger pointer-events-none"
                    fill="none"
                    strokeWidth="1.5"
                  >
                    <animate attributeName="r" values="18;34" dur="1.4s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.85;0" dur="1.4s" repeatCount="indefinite" />
                  </circle>
                )}

                {/* Outer halo */}
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={isFocused ? 24 : 18}
                  className={cn(
                    "transition-all duration-200",
                    isAttacker
                      ? "fill-danger/20 stroke-danger"
                      : isExfil
                        ? "fill-warn/20 stroke-warn"
                        : "fill-elevated stroke-border",
                    isFocused && "stroke-accent-fg stroke-2",
                    isTelemetryActive && "stroke-danger stroke-2",
                  )}
                  strokeWidth={isFocused ? 2 : 1.5}
                />

                {/* Node icon label */}
                <text
                  x={n.x}
                  y={n.y + 4}
                  textAnchor="middle"
                  className="fill-fg font-mono text-[9px] font-bold pointer-events-none"
                >
                  {isAttacker ? "ACTOR" : isExfil ? "CLOUD" : "HOST"}
                </text>

                {/* Bottom Node Name */}
                <text
                  x={n.x}
                  y={n.y + 30}
                  textAnchor="middle"
                  className={cn(
                    "fill-muted font-mono text-[9px] transition-colors pointer-events-none",
                    isHovered && "fill-fg font-semibold",
                  )}
                >
                  {n.label}
                </text>

                {/* Role label */}
                <text
                  x={n.x}
                  y={n.y + 40}
                  textAnchor="middle"
                  className="fill-subtle font-mono text-[8px] pointer-events-none"
                >
                  {n.role}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Information Banner */}
        {activeNode && (
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded bg-elevated px-3 py-1.5 text-xs border border-border">
            <div className="flex items-center gap-2">
              <span className="font-mono font-semibold text-fg">{activeNode.label}</span>
              <span className="text-muted">({activeNode.role})</span>
              <span className="rounded bg-accent/20 px-1.5 py-0.2 font-mono text-[10px] text-accent-fg">
                {activeNode.tier}
              </span>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-muted">Events: <strong className="text-fg">{activeNode.eventsCount}</strong></span>
              <span className="text-muted">|</span>
              <span className="text-danger">Techniques: {activeNode.techniques.join(", ")}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
