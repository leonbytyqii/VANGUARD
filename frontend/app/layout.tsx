import type { Metadata } from "next";
import "./globals.css";
import { AuthGate } from "@/components/layout/AuthGate";

export const metadata: Metadata = {
  title: "VANGUARD",
  description: "Agentic AI Security Operations Center",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-soc-bg text-soc-text antialiased">
        <AuthGate>{children}</AuthGate>
      </body>
    </html>
  );
}
