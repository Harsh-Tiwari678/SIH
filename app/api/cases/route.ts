import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. authorize — the user must have an application profile.
  const { data: profile } = await supabase
    .from("profiles")
    .select("id, role")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate input — parse and sanity-check the request body.
  let body: { case_number?: unknown; title?: unknown; description?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const case_number =
    typeof body.case_number === "string" ? body.case_number.trim() : "";
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const description =
    typeof body.description === "string" ? body.description.trim() : null;

  if (!case_number) {
    return NextResponse.json(
      { error: "case_number is required" },
      { status: 400 },
    );
  }
  if (!title) {
    return NextResponse.json({ error: "title is required" }, { status: 400 });
  }
  if (case_number.length > 100) {
    return NextResponse.json(
      { error: "case_number must be 100 characters or fewer" },
      { status: 400 },
    );
  }
  if (title.length > 500) {
    return NextResponse.json(
      { error: "title must be 500 characters or fewer" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // create_case SECURITY DEFINER RPC, atomically, with identity derived from
  // auth.uid() (never from client input). created_by / profile_id / role are
  // not reachable by the client on this path.
  const { data, error } = await supabase.rpc("create_case", {
    p_case_number: case_number,
    p_title: title,
    p_description: description,
  });

  if (error) {
    return NextResponse.json(
      { error: error.message },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ case: data }, { status: 201 });
}

function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("case_number_required") || message.includes("title_required")) {
    return 400;
  }
  if (message.includes("duplicate key") || message.toLowerCase().includes("unique")) {
    return 409;
  }
  return 500;
}
