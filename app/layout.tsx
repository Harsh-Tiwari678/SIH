import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { ThemeProvider } from "@/components/layout/theme-provider";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "Secure Evidence",
    template: "%s · Secure Evidence",
  },
  description:
    "Digital evidence management for law enforcement: integrity verification and chain-of-custody tracking.",
  applicationName: "Secure Evidence",
};

// Apply the persisted/resolved theme before first paint to avoid a flash
// between the server-rendered light default and the user's stored preference.
// Must match THEME_STORAGE_KEY and applyTheme() in the ThemeProvider.
const themeScript = `(function(){try{var k="secure-evidence-theme";var t=localStorage.getItem(k);var d=window.matchMedia("(prefers-color-scheme: dark)");var r=t==="dark"?"dark":t==="light"?"light":(d.matches?"dark":"light");document.documentElement.dataset.theme=r;}catch(e){}})()`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="min-h-dvh">
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}