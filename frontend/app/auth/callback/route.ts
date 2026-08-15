import { NextResponse, type NextRequest } from "next/server";

import { getSiteUrl, isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

function safeNextPath(value: string | null): string {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/";
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const next = safeNextPath(url.searchParams.get("next"));
  const siteUrl = getSiteUrl();
  const fallback = new URL("/login", siteUrl);

  if (!isSupabaseConfigured()) {
    fallback.searchParams.set("error", "configuration");
    return NextResponse.redirect(fallback);
  }

  const code = url.searchParams.get("code");
  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(new URL(next, siteUrl));
    }
  }

  fallback.searchParams.set("error", "callback");
  return NextResponse.redirect(fallback);
}
