import { describe, expect, it } from "vitest";
import { readJsonBounded, ResponseBodyTooLargeError } from "@gatopago/shared/http";

describe("bounded upstream JSON", () => {
	it("parses a response within the byte budget", async () => {
		const response = new Response(JSON.stringify({ ok: true, message: "á" }));
		await expect(readJsonBounded<{ ok: boolean }>(response, 128)).resolves.toEqual({
			ok: true,
			message: "á",
		});
	});

	it("rejects an oversized declared or streamed body", async () => {
		const declared = new Response("{}", { headers: { "content-length": "500" } });
		await expect(readJsonBounded(declared, 32)).rejects.toBeInstanceOf(ResponseBodyTooLargeError);

		const streamed = new Response(JSON.stringify({ data: "x".repeat(100) }));
		await expect(readJsonBounded(streamed, 32)).rejects.toBeInstanceOf(ResponseBodyTooLargeError);
	});

	it("rejects malformed JSON and invalid limits", async () => {
		await expect(readJsonBounded(new Response("not-json"), 32)).rejects.toBeInstanceOf(SyntaxError);
		await expect(readJsonBounded(new Response("{}"), 0)).rejects.toBeInstanceOf(RangeError);
	});
});
