import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    files: ["components/quantic-network-app.tsx"],
    rules: {
      // This component intentionally starts an external relay/IndexedDB sync from an effect.
      // A ref guard prevents overlapping syncs and cascading loops.
      "react-hooks/set-state-in-effect": "off",
    },
  },
  globalIgnores([".next/**", "out/**", "coverage/**"]),
]);
