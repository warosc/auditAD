/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // Proxy /api/* calls to the FastAPI backend.
  // In Docker: BACKEND_URL=http://panel-api:8080 (internal service name).
  // In dev:    set BACKEND_URL=http://localhost:8080 in .env.local
  async rewrites() {
    const backendUrl = process.env.BACKEND_URL || "http://panel-api:8080";
    return [
      {
        source:      "/api/:path*",
        destination: `${backendUrl}/:path*`,
      },
    ];
  },
};

export default nextConfig;
