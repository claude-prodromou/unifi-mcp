// src/cors.ts
import type { Env } from "./types";

/** Parse CORS_ALLOWED_ORIGINS into serialized origins, skipping invalid entries */
export function parseAllowedOrigins(value: string | undefined): Set<string> {
  const origins = new Set<string>();
  for (const entry of (value ?? "").split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    try {
      const origin = new URL(trimmed).origin;
      if (origin !== "null") origins.add(origin);
    } catch {
      // not an origin; ignore
    }
  }
  return origins;
}

/**
 * CORS headers for a request. The Origin is echoed only when it is listed in
 * CORS_ALLOWED_ORIGINS; otherwise no Access-Control-Allow-* header is sent and
 * browsers refuse the cross-origin read.
 */
export function corsHeaders(request: Request, env: Env): Record<string, string> {
  const headers: Record<string, string> = { Vary: "Origin" };
  const origin = request.headers.get("Origin");
  if (origin && parseAllowedOrigins(env.CORS_ALLOWED_ORIGINS).has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
  }
  return headers;
}
