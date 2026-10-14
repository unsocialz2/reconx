import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { SCANS_DIR } from "@/lib/paths";
import { guard } from "@/lib/api-security";
import { atomicJSON } from "@/lib/scan-manager";
const text = z
  .string()
  .max(4096)
  .refine((v) => !/[\r\n\0]/.test(v));
const schema = z
  .object({
    githubToken: text.optional(),
    chaosKey: text.optional(),
    shodanKey: text.optional(),
    virustotalKey: text.optional(),
    securitytrailsKey: text.optional(),
    orgName: text.optional(),
    customHeader: text.optional(),
    outputDir: text.optional(),
    verbose: z.boolean().optional(),
    noTimeout: z.boolean().optional(),
    htmlReport: z.boolean().optional(),
    jsonReport: z.boolean().optional(),
    saveRaw: z.boolean().optional(),
    workers: z.number().int().min(1).max(256).optional(),
  })
  .strict();
const file = path.join(SCANS_DIR, "reconx-gui-settings.json");
export async function GET(req: NextRequest) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    return NextResponse.json({
      settings: JSON.parse(await fs.readFile(file, "utf8")),
    });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      return NextResponse.json({ settings: { workers: 10 } });
    return NextResponse.json(
      { error: "Could not read settings" },
      { status: 500 },
    );
  }
}
export async function POST(req: NextRequest) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    await atomicJSON(file, schema.parse(await req.json()));
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json(
      { error: "Invalid settings or write failed" },
      { status: 400 },
    );
  }
}
