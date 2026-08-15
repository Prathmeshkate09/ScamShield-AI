import { redirect } from "next/navigation";

import { Dashboard } from "@/components/dashboard";
import { isSupabaseConfigured } from "@/lib/supabase/config";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  if (!isSupabaseConfigured()) {
    redirect("/login?error=configuration");
  }

  const supabase = await createClient();
  const { data } = await supabase.auth.getClaims();
  const claims = data?.claims;
  if (!claims?.sub) {
    redirect("/login");
  }

  const { data: { user } } = await supabase.auth.getUser();
  const userEmail = user?.email ?? (typeof claims.email === "string" ? claims.email : "Protected account");
  return <Dashboard userEmail={userEmail} />;
}
