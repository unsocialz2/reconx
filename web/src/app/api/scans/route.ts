import { NextRequest, NextResponse } from "next/server";
import { guard } from "@/lib/api-security";
import { launch, listScans } from "@/lib/scan-manager";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(req: NextRequest) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    return NextResponse.json({ scans: await listScans() });
  } catch {
    return NextResponse.json(
      { error: "Could not load scans" },
      { status: 500 },
    );
  }
}
export async function POST(req: NextRequest) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    return NextResponse.json(
      { scanId: await launch(await req.json()) },
      { status: 201 },
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : "Could not start scan",
      },
      { status: 400 },
    );
  }
}
