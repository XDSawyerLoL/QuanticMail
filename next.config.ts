import type { NextConfig } from "next";

const staticExport = process.env.QUANTIC_STATIC_EXPORT === "1";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  ...(staticExport
    ? {
        output: "export",
        basePath: "/mail",
        trailingSlash: true,
      }
    : {}),
};

export default nextConfig;
