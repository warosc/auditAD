import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // SOC dark palette
        soc: {
          bg:        "#080c14",
          surface:   "#0d1117",
          card:      "#111827",
          border:    "#1f2937",
          muted:     "#374151",
          text:      "#e5e7eb",
          dim:       "#9ca3af",
          accent:    "#6366f1",
          green:     "#10b981",
          red:       "#ef4444",
          yellow:    "#f59e0b",
          blue:      "#3b82f6",
          purple:    "#a855f7",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Cascadia Code", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
