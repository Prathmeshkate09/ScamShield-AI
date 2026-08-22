import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import { getAuthCookieOptions, getSupabaseConfig } from "@/lib/supabase/config";

const publicOnlyAuthPaths = new Set(["/login", "/signup", "/forgot-password", "/verify-email"]);
const accessibleAuthPaths = new Set([...publicOnlyAuthPaths, "/reset-password"]);

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
    cookieOptions: getAuthCookieOptions(),
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

  const { data: { user } } = await supabase.auth.getUser();
  const isSignedIn = Boolean(user?.id);
  const isEmailVerified = Boolean(user?.email_confirmed_at);
  const { pathname } = request.nextUrl;

  if (!isSignedIn && !accessibleAuthPaths.has(pathname) && !pathname.startsWith("/auth/")) {
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

  if (isSignedIn && !isEmailVerified && pathname !== "/verify-email" && !pathname.startsWith("/auth/")) {
    const verifyUrl = request.nextUrl.clone();
    verifyUrl.pathname = "/verify-email";
    verifyUrl.search = "";
    return redirectWithCookies(response, verifyUrl);
  }

  if (isSignedIn && isEmailVerified && publicOnlyAuthPaths.has(pathname)) {
    const dashboardUrl = request.nextUrl.clone();
    dashboardUrl.pathname = "/";
    dashboardUrl.search = "";
    return redirectWithCookies(response, dashboardUrl);
  }

  return response;
}
