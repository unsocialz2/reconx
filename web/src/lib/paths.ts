import path from "path";

export const PROJECT_ROOT = path.resolve(process.cwd(), "..");
export const BINARY_PATH = process.env.RECONX_BINARY || path.join(PROJECT_ROOT, "reconx");
export const SCANS_DIR = process.env.RECONX_SCANS_DIR || path.join(process.cwd(), "data", "scans");
export const OUTPUT_DIR = process.env.RECONX_OUTPUT_DIR || path.join(PROJECT_ROOT, "reconx-output");
