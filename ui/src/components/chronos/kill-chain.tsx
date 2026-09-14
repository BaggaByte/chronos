import { STAGES } from "@/lib/incident";
import { cn } from "@/lib/utils";

export function KillChain({ activeId }: { activeId?: string }) {
  return (
    <ol className="grid grid-cols-1 gap-2 sm:grid-cols-5">
      {STAGES.map((stage, i) => {
        const active = !activeId || activeId === stage.id;
        return (
          <li
            key={stage.id}
            className={cn(
              "relative rounded-md border bg-elevated px-3 py-3 transition-opacity duration-200",
              active ? "border-border opacity-100" : "border-border/60 opacity-50",
            )}
          >
            <p className="font-mono text-[10px] uppercase tracking-wider text-subtle">
              {String(i + 1).padStart(2, "0")}
            </p>
            <p className="mt-1 text-sm font-medium text-fg">{stage.label}</p>
            <p className="mt-1 font-mono text-[10px] text-muted">
              {stage.tactics.join(" · ")}
            </p>
          </li>
        );
      })}
    </ol>
  );
}
