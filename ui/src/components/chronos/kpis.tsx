import { report, attackerEvents, events } from "@/lib/incident";

const items = [
  { label: "Events ingested", value: String(report.total_events) },
  { label: "Attacker thread", value: String(attackerEvents.length) },
  { label: "Benign excluded", value: String(events.length - attackerEvents.length) },
  { label: "Techniques", value: String(Object.keys(report.technique_counts).length) },
  { label: "Spikes", value: String(report.spikes.length) },
  { label: "Dwell gaps", value: String(report.gaps.length) },
];

export function Kpis() {
  return (
    <section className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      {items.map((item) => (
        <article
          key={item.label}
          className="rounded-lg border border-border bg-surface px-3 py-3 shadow-panel sm:px-4"
        >
          <p className="text-[10px] font-medium uppercase tracking-wider text-subtle">
            {item.label}
          </p>
          <p className="mt-1 font-mono text-2xl font-medium tabular-nums tracking-tight text-fg">
            {item.value}
          </p>
        </article>
      ))}
    </section>
  );
}
