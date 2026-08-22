import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

import { getAuthCookieOptions, getSupabaseConfig } from "@/lib/supabase/config";

export async function createClient() {
  const config = getSupabaseConfig();
  if (!config) {
    throw new Error("Supabase authentication is not configured.");
  }

  const cookieStore = await cookies();

  return createServerClient(config.url, config.publishableKey, {
    cookieOptions: getAuthCookieOptions(),
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch (error) {
          const message = error instanceof Error ? error.message : "";
          if (!message.includes("Cookies can only be modified")) {
            throw error;
          }
          console.warn("auth.cookie_refresh_deferred", { errorType: error instanceof Error ? error.name : "UnknownError" });
        }
      }
    }
  });
}
