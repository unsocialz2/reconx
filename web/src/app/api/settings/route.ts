import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "fs";
import path from "path";
import { SCANS_DIR } from "@/lib/paths";

const SETTINGS_FILE = "reconx-gui-settings.json";

// GET /api/settings - Load saved settings
export async function GET() {
  try {
    const settingsPath = path.join(SCANS_DIR, SETTINGS_FILE);
    try {
      const content = await fs.readFile(settingsPath, "utf-8");
      const settings = JSON.parse(content);
      return NextResponse.json({ settings });
    } catch {
      // No settings file yet, return defaults
      return NextResponse.json({
        settings: {
          githubToken: "",
          chaosKey: "",
          shodanKey: "",
          virustotalKey: "",
          orgName: "",
          customHeader: "",
          outputDir: "",
          verbose: true,
          noTimeout: false,
          htmlReport: true,
          jsonReport: true,
          saveRaw: true,
          workers: 10,
        },
      });
    }
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to load settings", details: String(error) },
      { status: 500 }
    );
  }
}

// POST /api/settings - Save settings
export async function POST(request: NextRequest) {
  try {
    const settings = await request.json();

    await fs.mkdir(SETTINGS_DIR, { recursive: true });
    const settingsPath = path.join(SCANS_DIR, SETTINGS_FILE);
    await fs.writeFile(settingsPath, JSON.stringify(settings, null, 2));

    return NextResponse.json({ success: true, message: "Settings saved" });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to save settings", details: String(error) },
      { status: 500 }
    );
  }
}
