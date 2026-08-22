import { NextResponse, type NextRequest } from "next/server";

import { safeNextPath } from "@/lib/auth";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const next = safeNextPath(url.searchParams.get("next"));
  const siteUrl = request.nextUrl.origin;
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
      const response = NextResponse.redirect(new URL(next, siteUrl));
      if (next === "/reset-password") {
        response.cookies.set({
          name: "scamshield-recovery",
          value: "1",
          httpOnly: true,
          maxAge: 15 * 60,
          path: "/reset-password",
          sameSite: "lax",
          secure: request.nextUrl.protocol === "https:"
        });
      }
      return response;
    }
  }

  if (next === "/reset-password") {
    fallback.pathname = "/reset-password";
    fallback.searchParams.set("error", "invalid_link");
  } else {
    fallback.searchParams.set("error", "callback");
  }
  return NextResponse.redirect(fallback);
}
