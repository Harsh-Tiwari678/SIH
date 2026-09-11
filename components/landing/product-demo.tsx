"use client";

import * as React from "react";
import { Play, CheckCircle2, Upload, Fingerprint, Anchor } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/* The real Secure Evidence screen-recording will be placed in /public and
   referenced via DEMO_SRC. Until then the area shows a restrained placeholder
   that walks the actual on-screen workflow: upload, fingerprint, anchor,
   verify — it is a demo of what the recording will show, not a fake animation. */
const DEMO_SRC: string | null = null;

const STEPS = [
  { label: "Upload", icon: Upload },
  { label: "Fingerprint", icon: Fingerprint },
  { label: "Anchor", icon: Anchor },
  { label: "Verify", icon: CheckCircle2 },
];

export function ProductDemo() {
  const videoRef = React.useRef<HTMLVideoElement>(null);
  const [playing, setPlaying] = React.useState(false);

  const play = () => {
    const video = videoRef.current;
    if (video) {
      video.play();
    }
    setPlaying(true);
  };

  const stop = () => {
    const video = videoRef.current;
    if (video) {
      video.pause();
      video.currentTime = 0;
    }
    setPlaying(false);
  };

  return (
    <div className="w-full max-w-xl overflow-hidden rounded-xl border border-border bg-card shadow-lg shadow-black/[0.04] dark:shadow-black/[0.25]">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "size-2 rounded-full",
              playing ? "bg-success" : "bg-muted-foreground/30",
            )}
            aria-hidden
          />
          <span className="text-xs font-medium text-muted-foreground">
            Product Demo
          </span>
        </div>
        <span className="text-xs text-muted-foreground">0:00</span>
      </div>

      <div className="relative aspect-video bg-code-bg">
        {playing ? (
          /* Real recording loads here; falls back to the placeholder below. */
          DEMO_SRC ? (
            <video
              ref={videoRef}
              src={DEMO_SRC}
              controls
              playsInline
              className="absolute inset-0 size-full object-contain"
              aria-label="Secure Evidence product demo"
            />
          ) : (
            <div className="flex size-full flex-col items-center justify-center px-6 text-center">
              <p className="text-sm font-medium text-foreground">
                Screen recording not yet provided
              </p>
              <p className="mt-2 max-w-xs text-xs leading-relaxed text-muted-foreground">
                A real Secure Evidence recording will play here, showing upload,
                fingerprinting, anchoring, and independent on-chain verification.
              </p>
              <Button variant="outline" size="sm" className="mt-4" onClick={stop}>
                Stop
              </Button>
            </div>
          )
        ) : (
          <>
            {/* Poster / preview treatment — the actual upload-to-verify flow. */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="flex items-center gap-4 px-4">
                {STEPS.map((step, i) => (
                  <React.Fragment key={step.label}>
                    <div className="flex flex-col items-center gap-1.5">
                      <step.icon
                        className="size-4 text-muted-foreground"
                        aria-hidden
                      />
                      <span className="text-[0.65rem] font-medium text-muted-foreground">
                        {step.label}
                      </span>
                    </div>
                    {i < STEPS.length - 1 && (
                      <span className="h-px w-6 bg-border" aria-hidden />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            <button
              type="button"
              onClick={play}
              aria-label="Play product demo"
              className="group absolute inset-0 flex items-center justify-center rounded-xl bg-black/0 outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span className="flex size-14 items-center justify-center rounded-full border border-border bg-background/80 shadow-sm backdrop-blur-sm transition-transform duration-200 ease-out group-hover:scale-105 group-active:scale-95">
                <Play className="ml-0.5 size-5 text-foreground" fill="currentColor" aria-hidden />
              </span>
            </button>
          </>
        )}
      </div>
    </div>
  );
}
