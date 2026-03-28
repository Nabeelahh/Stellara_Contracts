import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { Instrument_Serif } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
});

const instrumentSerif = Instrument_Serif({
  subsets: ["latin"],
    weight: "400",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Stellara AI — Learn. Trade. Connect.",
  description:
    "An all-in-one Web3 academy combining AI-powered learning, social crypto insights, and real on-chain trading — built on Stellar.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.className} ${instrumentSerif.className} h-full antialiased`}>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
