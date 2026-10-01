import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import { defineConfig, globalIgnores } from "eslint/config";

export default defineConfig([
	globalIgnores(["node_modules", "worker-configuration.d.ts", ".wrangler"]),
	{
		files: ["src/**/*.ts", "test/**/*.ts", "test-worker/**/*.ts", "*.config.ts"],
		extends: [js.configs.recommended, tseslint.configs.recommended],
		languageOptions: {
			globals: {
				...globals.node,
				...globals.serviceworker,
				scheduler: "readonly",
			},
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
		rules: {
			"@typescript-eslint/no-floating-promises": ["error", { ignoreVoid: false }],
			"@typescript-eslint/no-misused-promises": "error",
		},
	},
]);
