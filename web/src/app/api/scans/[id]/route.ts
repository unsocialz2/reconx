import { NextRequest, NextResponse } from "next/server";
import { guard } from "@/lib/api-security";
import { scanDetails, stopScan } from "@/lib/scan-manager";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
type Context = { params: Promise<{ id: string }> };
export async function GET(req: NextRequest, ctx: Context) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    return NextResponse.json(await scanDetails((await ctx.params).id));
  } catch {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
}
export async function DELETE(req: NextRequest, ctx: Context) {
  const denied = guard(req);
  if (denied) return denied;
  try {
    await stopScan((await ctx.params).id);
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Scan is not running" }, { status: 409 });
  }
}
