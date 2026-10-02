import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const knip = fileURLToPath(new URL("../node_modules/knip/bin/knip.js", import.meta.url));
for (const args of [["--treat-config-hints-as-errors"], ["--cycles"]]) {
	const result = spawnSync(process.execPath, [knip, ...args], {
		stdio: "inherit",
		// Oxc's experimental raw parser reserves a 6 GiB buffer per parse.
		env: { ...process.env, KNIP_DISABLE_RAW_TRANSFER: "1" },
	});
	if (result.error) throw result.error;
	if (result.status !== 0) process.exit(result.status ?? 1);
}
