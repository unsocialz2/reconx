import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";
export function guard(req: NextRequest): NextResponse | null {
  const token = process.env.RECONX_WEB_TOKEN;
  const host = req.nextUrl.hostname;
  if (token) {
    const auth = req.headers.get("authorization") || "";
    let supplied = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (auth.startsWith("Basic "))
      supplied = Buffer.from(auth.slice(6), "base64")
        .toString()
        .split(":")
        .slice(1)
        .join(":");
    const a = Buffer.from(supplied),
      b = Buffer.from(token);
    if (a.length !== b.length || !timingSafeEqual(a, b))
      return new NextResponse("Authentication required", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="ReconX"' },
      });
  } else if (!["localhost", "127.0.0.1", "[::1]"].includes(host)) {
    return NextResponse.json(
      { error: "Remote access requires RECONX_WEB_TOKEN" },
      { status: 403 },
    );
  }
  const origin = req.headers.get("origin");
  if (req.method !== "GET" && origin && origin !== req.nextUrl.origin)
    return NextResponse.json(
      { error: "Cross-origin write rejected" },
      { status: 403 },
    );
  return null;
}
