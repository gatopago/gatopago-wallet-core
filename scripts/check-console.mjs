import { readdir, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";

const sourceRoot = path.resolve(import.meta.dirname, "../src");
const ts = createRequire(path.join(sourceRoot, "../package.json"))("typescript");
const logMethods = new Set(["debug", "error", "info", "log", "warn"]);

async function sourceFiles(directory) {
	const entries = await readdir(directory, { withFileTypes: true });
	const nested = await Promise.all(
		entries.map((entry) => {
			const target = path.join(directory, entry.name);
			if (entry.isDirectory()) return sourceFiles(target);
			return entry.isFile() && entry.name.endsWith(".ts") ? [target] : [];
		}),
	);
	return nested.flat();
}

const violations = [];
for (const file of await sourceFiles(sourceRoot)) {
	const source = ts.createSourceFile(file, await readFile(file, "utf8"), ts.ScriptTarget.Latest, true);
	function visit(node) {
		if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
			&& ts.isIdentifier(node.expression.expression) && node.expression.expression.text === "console"
			&& logMethods.has(node.expression.name.text)) {
			const [payload] = node.arguments;
			const structured = node.arguments.length === 1 && ts.isObjectLiteralExpression(payload)
				&& payload.properties.some(property => ts.isPropertyAssignment(property)
					&& (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))
					&& property.name.text === "event" && ts.isStringLiteral(property.initializer)
					&& property.initializer.text.length > 0);
			if (!structured) {
				const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
				violations.push(`${path.relative(process.cwd(), file)}:${line + 1}`);
			}
		}
		ts.forEachChild(node, visit);
	}
	visit(source);
}

if (violations.length > 0) {
	console.error(`Unstructured Wallet Core console calls:\n${violations.map((item) => `- ${item}`).join("\n")}`);
	process.exit(1);
}

console.log("Wallet Core logs are structured.");
