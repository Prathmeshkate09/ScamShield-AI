import { createBrowserClient } from "@supabase/ssr";

import { getSupabaseConfig } from "@/lib/supabase/config";

export function createClient() {
  const config = getSupabaseConfig();
  if (!config) {
    throw new Error("Supabase authentication is not configured.");
  }

  return createBrowserClient(config.url, config.publishableKey);
}
