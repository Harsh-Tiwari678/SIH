import { ThemeToggle } from "@/components/layout/theme-toggle";
import { ProductMark } from "@/components/layout/product-mark";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <header className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
        <ProductMark />
        <ThemeToggle />
      </header>
      <div className="flex flex-1 flex-col">{children}</div>
    </div>
  );
}