import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import { getSupabaseConfig } from "@/lib/supabase/config";

const authPaths = new Set(["/login", "/signup", "/forgot-password", "/reset-password"]);

function redirectWithCookies(response: NextResponse, destination: URL): NextResponse {
  const redirect = NextResponse.redirect(destination);
  response.cookies.getAll().forEach((cookie) => redirect.cookies.set(cookie));
  return redirect;
}

export async function updateSession(request: NextRequest): Promise<NextResponse> {
  const config = getSupabaseConfig();
  if (!config) {
    return NextResponse.next({ request });
  }

  let response = NextResponse.next({ request });
  const supabase = createServerClient(config.url, config.publishableKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
        response = NextResponse.next({ request });
        cookiesToSet.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
      }
    }
  });

  const { data } = await supabase.auth.getClaims();
  const claims = data?.claims;
  const isSignedIn = Boolean(claims?.sub);
  const { pathname } = request.nextUrl;

  if (!isSignedIn && !authPaths.has(pathname) && !pathname.startsWith("/auth/")) {
    const hasExpiredOAuthState = request.nextUrl.searchParams.get("error_code") === "bad_oauth_state";
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.search = "";
    loginUrl.searchParams.set("next", pathname);
    if (hasExpiredOAuthState) {
      loginUrl.searchParams.set("error", "oauth_state");
    }
    return redirectWithCookies(response, loginUrl);
  }

  if (isSignedIn && authPaths.has(pathname)) {
    const dashboardUrl = request.nextUrl.clone();
    dashboardUrl.pathname = "/";
    dashboardUrl.search = "";
    return redirectWithCookies(response, dashboardUrl);
  }

  return response;
}
