"use client";

import * as React from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme, type Theme } from "./theme-provider";

const OPTIONS: {
  value: Theme;
  label: string;
  Icon: typeof Sun;
}[] = [
  { value: "system", label: "System theme", Icon: Monitor },
  { value: "light", label: "Light theme", Icon: Sun },
  { value: "dark", label: "Dark theme", Icon: Moon },
];

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div
      className="flex h-8 items-center gap-0.5 rounded-lg border border-border bg-background p-0.5"
      role="group"
      aria-label="Color theme"
    >
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = theme === value;
        return (
          <Button
            key={value}
            type="button"
            variant={active ? "secondary" : "ghost"}
            size="icon-sm"
            aria-pressed={active}
            aria-label={label}
            title={label}
            onClick={() => setTheme(value)}
            className="bg-transparent"
          >
            <Icon className="size-4" />
          </Button>
        );
      })}
    </div>
  );
}