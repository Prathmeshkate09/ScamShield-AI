import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true
};

if (process.env.DOCKER_BUILD === "true") {
  nextConfig.output = "standalone";
}

export default nextConfig;
