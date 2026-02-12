import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Envelope Encryption Demo",
  description: "AES-256-GCM envelope encryption with TurboRepo monorepo",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
