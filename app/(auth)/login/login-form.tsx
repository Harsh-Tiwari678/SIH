"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { createClient } from "@/lib/supabase/client";

export default function LoginForm() {
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);

    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");

    const supabase = createClient();

    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setError(error.message);
      setLoading(false);
      return;
    }

    router.push("/dashboard");
    await router.refresh();
  }

  return (
    <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
      <Input
        type="email"
        name="email"
        placeholder="Email"
        autoComplete="email"
        required
      />

      <Input
        type="password"
        name="password"
        placeholder="Password"
        autoComplete="current-password"
        required
      />

      <Button type="submit" disabled={loading} className="w-full">
        {loading ? (
          <Loader2 className="size-4 animate-spin" aria-hidden />
        ) : null}
        {loading ? "Signing in..." : "Sign in"}
      </Button>

      {error && (
        <p
          role="alert"
          className="flex items-center gap-1.5 text-sm text-danger"
        >
          <AlertCircle className="size-4 shrink-0" aria-hidden />
          <span>{error}</span>
        </p>
      )}
    </form>
  );
}