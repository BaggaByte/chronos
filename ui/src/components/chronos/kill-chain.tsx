import { STAGES } from "@/lib/incident";
import { cn } from "@/lib/utils";

export function KillChain({ activeId }: { activeId?: string }) {
  return (
    <ol className="grid grid-cols-1 gap-2 sm:grid-cols-5">
      {STAGES.map((stage, i) => {
        const isCurrent = activeId === stage.id;
        const active = !activeId || isCurrent;
        return (
          <li
            key={stage.id}
            className={cn(
              "relative rounded-md border bg-elevated px-3 py-3 transition-all duration-300",
              isCurrent
                ? "border-danger/80 bg-danger/10 shadow-[0_0_15px_rgba(196,92,92,0.2)] ring-1 ring-danger/50"
                : active
                  ? "border-border opacity-100"
                  : "border-border/50 opacity-40",
            )}
          >
            <div className="flex items-center justify-between">
              <p
                className={cn(
                  "font-mono text-[10px] uppercase tracking-wider",
                  isCurrent ? "font-semibold text-danger" : "text-subtle",
                )}
              >
                {String(i + 1).padStart(2, "0")}
              </p>
              {isCurrent && (
                <span className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-wider text-danger">
                  <span className="size-1.5 animate-ping rounded-full bg-danger"></span>
                  Active Stage
                </span>
              )}
            </div>
            <p
              className={cn(
                "mt-1 text-sm font-medium transition-colors",
                isCurrent ? "text-danger" : "text-fg",
              )}
            >
              {stage.label}
            </p>
            <p className="mt-1 font-mono text-[10px] text-muted">
              {stage.tactics.join(" · ")}
            </p>
          </li>
        );
      })}
    </ol>
  );
}
