import { ShieldCheck } from "lucide-react";

export function ProductMark() {
  return (
    <span className="inline-flex items-center gap-2">
      <ShieldCheck className="size-5 shrink-0 text-primary" aria-hidden />
      <span className="text-sm font-semibold tracking-tight">Secure Evidence</span>
    </span>
  );
}