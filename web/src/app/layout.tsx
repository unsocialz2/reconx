import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

export const metadata: Metadata = {
  title: "ReconX — Bug Bounty Reconnaissance",
  description:
    "Web GUI for ReconX automated reconnaissance tool. Configure, launch, and monitor bug bounty scans.",
  icons: {
    icon: "/logo.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        className={"antialiased"}
        style={{ backgroundColor: "#0a0c0f", color: "#e5e7eb" }}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
