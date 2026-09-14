import { cn } from "@/lib/utils";
import type { HTMLAttributes } from "react";

const tones: Record<string, string> = {
  default: "border-border text-muted bg-elevated",
  high: "border-danger/40 text-danger bg-danger/10",
  medium: "border-warn/40 text-warn bg-warn/10",
  low: "border-ok/40 text-ok bg-ok/10",
  info: "border-info/40 text-info bg-info/10",
  accent: "border-accent/30 text-fg bg-elevated",
};

export function Badge({
  className,
  tone = "default",
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: keyof typeof tones | string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        tones[tone] ?? tones.default,
        className,
      )}
      {...props}
    />
  );
}
