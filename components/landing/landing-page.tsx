import Link from "next/link";
import {
  ShieldCheck,
  Shield,
  Lock,
  FileCheck,
  Users,
  Upload,
  Fingerprint,
  Archive,
  Anchor,
  CheckCircle2,
  ArrowRight,
  type LucideIcon,
} from "lucide-react";
import { LandingNavbar } from "@/components/landing/navbar";
import { ProductDemo } from "@/components/landing/product-demo";

/* ─── Internal: Section heading ────────────────────────────────────────── */

function SectionHeading({
  label,
  title,
  description,
}: {
  label: string;
  title: string;
  description?: string;
}) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <p className="mb-3 text-xs font-medium uppercase tracking-widest text-teal">
        {label}
      </p>
      <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">
        {title}
      </h2>
      {description && (
        <p className="mt-4 text-base leading-relaxed text-muted-foreground">
          {description}
        </p>
      )}
    </div>
  );
}

/* ─── Internal: Platform capability card ────────────────────────────────── */

function CapabilityCard({
  icon: Icon,
  title,
  description,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <Icon className="mb-3 size-5 text-teal" aria-hidden />
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
        {description}
      </p>
    </div>
  );
}

/* ─── Internal: Workflow step ──────────────────────────────────────────── */

function WorkflowStep({
  icon: Icon,
  label,
}: {
  icon: LucideIcon;
  label: string;
}) {
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="flex size-10 items-center justify-center rounded-lg border border-border bg-card">
        <Icon className="size-5 text-muted-foreground" aria-hidden />
      </div>
      <span className="text-xs font-medium text-muted-foreground">
        {label}
      </span>
    </div>
  );
}

/* ─── Internal: Workflow connector ─────────────────────────────────────── */

function WorkflowConnector() {
  return (
    <div className="hidden w-12 shrink-0 items-center justify-center sm:flex">
      <ArrowRight className="size-4 text-muted-foreground/40" aria-hidden />
    </div>
  );
}

/* ─── Internal: Evidence integrity mock card ────────────────────────────── */

function IntegrityMock() {
  return (
    <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-lg shadow-black/[0.04] dark:shadow-black/[0.2]">
      <div className="border-b border-border px-5 py-3">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Evidence Detail
        </p>
      </div>
      <div className="space-y-4 p-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">Evidence</p>
            <p className="mt-0.5 text-sm font-medium">yami.jpg</p>
          </div>
          <span className="rounded-full bg-success/10 px-2 py-0.5 text-xs font-medium text-success">
            Verified
          </span>
        </div>
        <div className="h-px bg-border" />
        <div>
          <p className="text-xs text-muted-foreground">SHA-256</p>
          <p className="mt-0.5 font-mono text-xs break-all text-muted-foreground">
            db34d41a89b6e04f4e8c5d2a1f7b9e3c6d8a2b4f0e5c7d9a1b3f6e8c2d4a
          </p>
        </div>
        <div className="flex gap-6">
          <div>
            <p className="text-xs text-muted-foreground">Blockchain</p>
            <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-teal">
              <Anchor className="size-3" aria-hidden />
              Anchored
            </span>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Verification</p>
            <span className="mt-0.5 inline-flex items-center gap-1 text-xs font-medium text-success">
              <CheckCircle2 className="size-3" aria-hidden />
              Verified
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Internal: Chain of custody timeline ──────────────────────────────── */

function CustodyTimeline() {
  const events = [
    { label: "Received", color: "bg-primary" },
    { label: "Transferred", color: "bg-primary" },
    { label: "Accessed", color: "bg-primary" },
    { label: "Returned", color: "bg-success" },
  ];
  return (
    <div className="flex flex-col items-center gap-0">
      {events.map((e, i) => (
        <div key={e.label} className="flex flex-col items-center">
          <div className="flex items-center gap-3">
            <span className={`size-2.5 rounded-full ${e.color}`} />
            <span className="text-sm font-medium">{e.label}</span>
          </div>
          {i < events.length - 1 && (
            <div className="my-1 ml-1.5 h-6 w-px bg-border" />
          )}
        </div>
      ))}
    </div>
  );
}

/* ─── Internal: Security architecture layer ────────────────────────────── */

function SecurityLayer({
  icon: Icon,
  label,
}: {
  icon: LucideIcon;
  label: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-border bg-card px-4 py-2.5">
      <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

/* ─── Internal: FAQ item ───────────────────────────────────────────────── */

function FaqItem({
  question,
  answer,
}: {
  question: string;
  answer: string;
}) {
  return (
    <div className="border-b border-border py-5 last:border-b-0">
      <h3 className="text-sm font-semibold">{question}</h3>
      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
        {answer}
      </p>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   PUBLIC EXPORT: LandingPage
   ═══════════════════════════════════════════════════════════════════════════ */

export function LandingPage() {
  return (
    <div className="min-h-dvh bg-background text-foreground">
      {/* ── 1. Navbar ───────────────────────────────────────────────── */}
      <LandingNavbar />

      {/* ── 2. Hero ─────────────────────────────────────────────────── */}
      <section className="px-5 py-16 sm:py-20">
        <div className="mx-auto max-w-6xl">
          <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)] lg:gap-12">
            <div className="max-w-xl">
              <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl lg:text-[2.6rem] lg:leading-[1.08]">
                Evidence you can
                <br />
                verify.
              </h1>
              <p className="mt-4 max-w-lg text-base leading-relaxed text-muted-foreground">
                Securely manage digital evidence, preserve its chain of custody,
                and independently verify its integrity.
              </p>
              <div className="mt-7 flex flex-wrap items-center gap-3">
                <Link
                  href="/login"
                  className="inline-flex h-9 items-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
                >
                  Get Started
                </Link>
                <a
                  href="#workflow"
                  className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-border px-4 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                >
                  See How It Works
                  <ArrowRight className="size-3.5" aria-hidden />
                </a>
              </div>
            </div>

            <div className="flex justify-center lg:justify-end">
              <ProductDemo />
            </div>
          </div>
        </div>
      </section>

      {/* ── 3. Problem ──────────────────────────────────────────────── */}
      <section className="border-y border-border bg-muted/40 px-5 py-20">
        <div className="mx-auto max-w-6xl">
          <SectionHeading
            label="The Problem"
            title="Digital evidence is fragile"
            description="Files can be copied, modified, or moved between investigators. Without a reliable verification mechanism, proving that evidence is authentic and unaltered is difficult."
          />
          <div className="mx-auto mt-12 grid max-w-3xl gap-6 sm:grid-cols-3">
            {[
              {
                title: "Tampering risk",
                desc: "Digital files can be altered without leaving visible traces.",
              },
              {
                title: "Chain gaps",
                desc: "Tracking who accessed evidence, and when, is essential but often incomplete.",
              },
              {
                title: "Verification burden",
                desc: "There is no universal way to prove that evidence has not changed between collection and presentation.",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="rounded-xl border border-border bg-card p-5"
              >
                <h3 className="text-sm font-semibold">{item.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── 4. Platform Overview ────────────────────────────────────── */}
      <section id="platform" className="px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <SectionHeading
            label="Platform"
            title="Built for evidence integrity"
            description="Secure Evidence provides the tools investigators need to manage, protect, and verify digital evidence."
          />
          <div className="mx-auto mt-12 grid max-w-4xl gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <CapabilityCard
              icon={ShieldCheck}
              title="Secure Evidence"
              description="Private storage with controlled access. Every document is stored with encrypted access controls."
            />
            <CapabilityCard
              icon={Fingerprint}
              title="Integrity"
              description="SHA-256 fingerprinting detects any changes. The fingerprint is computed server-side at upload."
            />
            <CapabilityCard
              icon={Users}
              title="Chain of Custody"
              description="Track evidence handling over time. Every access, transfer, and action is recorded."
            />
            <CapabilityCard
              icon={Anchor}
              title="Blockchain Verification"
              description="Anchor evidence fingerprints to a blockchain and independently verify them at any time."
            />
            <CapabilityCard
              icon={Lock}
              title="Role-Based Access"
              description="Authorized team members access only what they need. Roles are enforced server-side."
            />
            <CapabilityCard
              icon={FileCheck}
              title="Case Collaboration"
              description="Work together on cases with controlled membership. Evidence stays protected."
            />
          </div>
        </div>
      </section>

      {/* ── 5. How It Works ─────────────────────────────────────────── */}
      <section id="workflow" className="border-y border-border bg-muted/40 px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <SectionHeading
            label="How It Works"
            title="From upload to verification"
            description="A clear, auditable process for preserving and verifying evidence integrity."
          />
          <div className="mt-12 flex flex-wrap items-center justify-center gap-2 sm:gap-0">
            <WorkflowStep icon={Upload} label="Upload" />
            <WorkflowConnector />
            <WorkflowStep icon={Fingerprint} label="Fingerprint" />
            <WorkflowConnector />
            <WorkflowStep icon={Archive} label="Preserve" />
            <WorkflowConnector />
            <WorkflowStep icon={Anchor} label="Anchor" />
            <WorkflowConnector />
            <WorkflowStep icon={CheckCircle2} label="Verify" />
          </div>
        </div>
      </section>

      {/* ── 6. Evidence Integrity ────────────────────────────────────── */}
      <section className="px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <div className="grid items-center gap-12 lg:grid-cols-2 lg:gap-16">
            <div>
              <SectionHeading
                label="Integrity"
                title="Independently verifiable"
                description="Every evidence item receives a SHA-256 fingerprint at upload. That fingerprint is anchored to the blockchain. Verification compares the current fingerprint against the anchor to confirm nothing has changed."
              />
            </div>
            <div className="flex justify-center">
              <IntegrityMock />
            </div>
          </div>
        </div>
      </section>

      {/* ── 7. Chain of Custody ─────────────────────────────────────── */}
      <section className="border-y border-border bg-muted/40 px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <div className="grid items-center gap-12 lg:grid-cols-2 lg:gap-16">
            <div className="flex justify-center lg:order-1">
              <CustodyTimeline />
            </div>
            <div className="lg:order-2">
              <SectionHeading
                label="Chain of Custody"
                title="Every action recorded"
                description="Evidence handling events are logged against each evidence item and version. Transfers, access events, and returns are tracked with timestamps and responsible parties."
              />
            </div>
          </div>
        </div>
      </section>

      {/* ── 8. Multi-Agency Collaboration ───────────────────────────── */}
      <section className="px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <div className="grid items-center gap-12 lg:grid-cols-2 lg:gap-16">
            <div>
              <SectionHeading
                label="Collaboration"
                title="Controlled case access"
                description="Organizations collaborate through controlled case membership. Authorized team members can work together on shared cases without exposing evidence to unauthorized users."
              />
            </div>
            <div className="flex justify-center">
              <div className="flex flex-col items-center gap-0">
                {["Organization", "Case", "Authorized Members", "Evidence"].map(
                  (label, i) => (
                    <div key={label} className="flex flex-col items-center">
                      <div className="flex items-center gap-3">
                        <span className="size-2 rounded-full bg-primary" />
                        <span className="text-sm font-medium">{label}</span>
                      </div>
                      {i < 3 && (
                        <div className="my-1 ml-1.5 h-6 w-px bg-border" />
                      )}
                    </div>
                  ),
                )}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── 9. Security Architecture ────────────────────────────────── */}
      <section id="security" className="border-y border-border bg-muted/40 px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-6xl">
          <SectionHeading
            label="Security"
            title="Layered by design"
            description="Every layer enforces its own controls. No single layer is the sole point of protection."
          />
          <div className="mx-auto mt-12 grid max-w-2xl gap-2">
            <SecurityLayer icon={Shield} label="Authentication" />
            <SecurityLayer icon={Lock} label="Authorization" />
            <SecurityLayer icon={ShieldCheck} label="Row-Level Security" />
            <SecurityLayer icon={Lock} label="Private Storage" />
            <SecurityLayer icon={Fingerprint} label="SHA-256 Integrity" />
            <SecurityLayer icon={FileCheck} label="Audit & Chain of Custody" />
            <SecurityLayer icon={Anchor} label="Blockchain Verification" />
          </div>
        </div>
      </section>

      {/* ── 10. FAQ ─────────────────────────────────────────────────── */}
      <section className="px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-2xl">
          <SectionHeading label="FAQ" title="Common questions" />
          <div className="mt-12">
            <FaqItem
              question="How is evidence integrity verified?"
              answer="When evidence is uploaded, a SHA-256 fingerprint is computed server-side. That fingerprint is anchored to the blockchain. Verification compares the current fingerprint against the on-chain anchor to confirm the evidence has not been altered."
            />
            <FaqItem
              question="What is recorded on the blockchain?"
              answer="The evidence fingerprint (SHA-256 hash) and a case identifier are anchored on-chain. The actual evidence files and metadata remain in private storage."
            />
            <FaqItem
              question="Who can access evidence?"
              answer="Only users who are members of a case, with an appropriate role, can access its evidence. Access is enforced at the database level through Row-Level Security policies."
            />
            <FaqItem
              question="How does chain of custody work?"
              answer="Every handling event (upload, access, transfer, return) is recorded against the evidence item with a timestamp and the responsible party. These records are append-only."
            />
            <FaqItem
              question="Can evidence be changed after upload?"
              answer="Evidence is versioned. New versions create new records; existing versions are never overwritten. The fingerprint of each version is independently anchored and verifiable."
            />
          </div>
        </div>
      </section>

      {/* ── 11. Final CTA ───────────────────────────────────────────── */}
      <section className="border-y border-border bg-muted/40 px-5 py-20 sm:py-28">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Preserve evidence. Prove integrity.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-muted-foreground">
            Get started with Secure Evidence to manage and verify your digital
            evidence with confidence.
          </p>
          <div className="mt-8">
            <Link
              href="/login"
              className="inline-flex h-9 items-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              Get Started
            </Link>
          </div>
        </div>
      </section>

      {/* ── 12. Footer ──────────────────────────────────────────────── */}
      <footer className="px-5 py-10">
        <div className="mx-auto flex max-w-6xl flex-col items-center gap-3 sm:flex-row sm:justify-between">
          <div className="inline-flex items-center gap-2">
            <ShieldCheck className="size-4 text-muted-foreground" aria-hidden />
            <span className="text-xs text-muted-foreground">
              Secure Evidence
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Digital evidence management and integrity verification.
          </p>
        </div>
      </footer>
    </div>
  );
}
