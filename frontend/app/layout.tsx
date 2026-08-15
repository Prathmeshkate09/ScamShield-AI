import type { Metadata } from "next";
import { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: "ScamShield AI | Detect the scam before you take the bait.",
  description: "An explainable AI security assistant for suspicious messages, screenshots, URLs, and voice transcripts."
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
