"use client";

import { useEffect, useState } from "react";

type Case = {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

type State =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "error" }
  | { status: "empty" }
  | { status: "ready"; cases: Case[] };

export default function CaseList() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const res = await fetch("/api/cases", { cache: "no-store" });
      if (cancelled) return;

      if (res.status === 401) {
        setState({ status: "unauthorized" });
        return;
      }
      if (!res.ok) {
        setState({ status: "error" });
        return;
      }

      const data = (await res.json()) as { cases: Case[] };
      if (data.cases.length === 0) {
        setState({ status: "empty" });
      } else {
        setState({ status: "ready", cases: data.cases });
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.status === "loading") {
    return <p className="text-sm text-zinc-600">Loading cases…</p>;
  }

  if (state.status === "unauthorized") {
    return (
      <p className="text-sm text-red-600">
        Your session has expired. Please sign in again.
      </p>
    );
  }

  if (state.status === "error") {
    return (
      <p className="text-sm text-red-600">
        Failed to load cases. Please try again later.
      </p>
    );
  }

  if (state.status === "empty") {
    return <p className="text-sm text-zinc-600">No cases found.</p>;
  }

  return (
    <ul className="divide-y divide-zinc-200 rounded-md border border-zinc-200">
      {state.cases.map((caseRow) => (
        <li key={caseRow.id} className="flex items-start justify-between gap-4 p-4">
          <div>
            <p className="text-sm font-medium text-zinc-900">
              {caseRow.case_number}
            </p>
            <p className="mt-0.5 text-sm text-zinc-600">{caseRow.title}</p>
            {caseRow.description ? (
              <p className="mt-1 text-sm text-zinc-500">{caseRow.description}</p>
            ) : null}
          </div>
          <span className="shrink-0 rounded-full border border-zinc-300 px-2 py-0.5 text-xs text-zinc-600">
            {caseRow.status}
          </span>
        </li>
      ))}
    </ul>
  );
}
