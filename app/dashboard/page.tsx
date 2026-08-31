import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import CaseList from "./case-list";
import LogoutButton from "./logout-button";

export default async function DashboardPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  return (
    <main className="flex flex-1 flex-col items-center px-4 py-8">
      <div className="w-full max-w-2xl space-y-6">
        <div className="rounded-lg border border-zinc-200 bg-white p-8 shadow-sm">
          <h1 className="text-xl font-semibold text-zinc-900">Dashboard</h1>
          <p className="mt-1 text-sm text-zinc-600">
            Signed in with the following account.
          </p>

          <dl className="mt-6 flex flex-col gap-4 text-sm">
            <div>
              <dt className="font-medium text-zinc-500">Email</dt>
              <dd className="mt-0.5 text-zinc-900">{user.email}</dd>
            </div>
          </dl>

          <div className="mt-8">
            <LogoutButton />
          </div>
        </div>

        <section className="rounded-lg border border-zinc-200 bg-white p-8 shadow-sm">
          <h2 className="text-lg font-semibold text-zinc-900">Your cases</h2>
          <p className="mt-1 text-sm text-zinc-600">
            Cases created by you or that you are a member of.
          </p>
          <div className="mt-6">
            <CaseList />
          </div>
        </section>
      </div>
    </main>
  );
}