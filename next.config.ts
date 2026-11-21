import type { NextConfig } from "next";

const staticExport = process.env.QUANTIC_STATIC_EXPORT === "1";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  ...(!staticExport ? {async headers() {
    return [{source:"/:path*",headers:[
      {key:"X-Content-Type-Options",value:"nosniff"},
      {key:"Referrer-Policy",value:"no-referrer"},
      {key:"Content-Security-Policy",value:"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"},
    ]}];
  }} : {}),
  ...(staticExport
    ? {
        output: "export",
        basePath: "/mail",
        trailingSlash: true,
      }
    : {}),
};

export default nextConfig;
