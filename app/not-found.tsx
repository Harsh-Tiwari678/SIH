import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-2 bg-background px-4 text-center">
      <p className="font-mono text-sm text-muted-foreground">404</p>
      <h1 className="text-lg font-semibold text-foreground">Page not found</h1>
      <p className="max-w-sm text-sm text-muted-foreground">
        The requested page does not exist, or you do not have access to it.
      </p>
      <Button className="mt-4" asChild>
        <Link href="/">Back to home</Link>
      </Button>
    </main>
  );
}