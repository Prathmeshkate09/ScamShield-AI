import { NextResponse } from "next/server";

export async function POST() {
  const response = NextResponse.json({ success: true });
  response.cookies.set({
    name: "scamshield-recovery",
    value: "",
    httpOnly: true,
    maxAge: 0,
    path: "/reset-password",
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  });
  return response;
}
