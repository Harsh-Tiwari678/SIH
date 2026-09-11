export default function Loading() {
  return (
    <div className="flex min-h-dvh items-center justify-center bg-background">
      <span
        className="size-8 animate-pulse rounded-lg bg-muted"
        aria-hidden
      />
      <span className="sr-only">Loading…</span>
    </div>
  );
}