import { NextRequest, NextResponse } from "next/server";

export const maxDuration = 60;
export const runtime = "nodejs";

const SCANNER_URL = process.env.SCANNER_URL;
const SCANNER_API_KEY = process.env.SCANNER_API_KEY;

export async function POST(req: NextRequest) {
  const { repoUrl } = await req.json();

  if (!repoUrl || typeof repoUrl !== "string" || !repoUrl.includes("github.com")) {
    return NextResponse.json({ error: "Invalid GitHub URL" }, { status: 400 });
  }

  if (!SCANNER_URL || !SCANNER_API_KEY) {
    return NextResponse.json({ error: "Scanner not configured." }, { status: 500 });
  }

  try {
    const res = await fetch(`${SCANNER_URL.replace(/\/$/, '')}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": SCANNER_API_KEY,
      },
      body: JSON.stringify({ repoUrl }),
      signal: AbortSignal.timeout(15000),
    });

    const data = await res.json();

    if (!res.ok) {
      return NextResponse.json(
        { error: data.error || "Scanner error" },
        { status: res.status }
      );
    }

    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message || "Failed to reach scanner backend" },
      { status: 500 }
    );
  }
}
