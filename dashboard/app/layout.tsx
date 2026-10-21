import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cypher 2.0 — Network Threat Visibility",
  description: "Deep packet analysis, deterministic rules, and ML flow scoring with MITRE ATT&CK mapping.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
