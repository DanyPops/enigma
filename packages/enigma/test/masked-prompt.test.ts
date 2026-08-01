import { describe, expect, it } from "bun:test";
import { PassThrough } from "node:stream";
import { promptMaskedSecret } from "../src/masked-prompt.ts";

/** A PassThrough that also reports as a TTY, matching a real interactive terminal's stream shape. */
function ttyInput(): PassThrough & { isTTY: true } {
	const stream = new PassThrough() as PassThrough & { isTTY: true };
	stream.isTTY = true;
	return stream;
}

describe("promptMaskedSecret", () => {
	it("resolves with the typed value while never writing it to output (TTY path)", async () => {
		const input = ttyInput();
		const output = new PassThrough();
		let written = "";
		output.on("data", (chunk) => {
			written += chunk.toString();
		});

		const promise = promptMaskedSecret("Paste the key: ", input, output);
		input.write("my-secret-key");
		input.write("\r");

		const value = await promise;
		expect(value).toBe("my-secret-key");
		expect(written).not.toContain("my-secret-key");
		expect(written).toContain("Paste the key: ");
	});

	it("trims trailing whitespace from the typed value", async () => {
		const input = ttyInput();
		const output = new PassThrough();
		output.on("data", () => {});

		const promise = promptMaskedSecret("Key: ", input, output);
		input.write("  padded-key  ");
		input.write("\r");

		expect(await promise).toBe("padded-key");
	});

	it("reads one line from stdin unmasked when input is not a TTY (piped, e.g. from a password manager)", async () => {
		const input = new PassThrough(); // isTTY is false/undefined by default
		const output = new PassThrough();

		const promise = promptMaskedSecret("Key: ", input, output);
		input.end("piped-secret\n");

		expect(await promise).toBe("piped-secret");
	});

	it("only takes the first line when piped input carries more than one", async () => {
		const input = new PassThrough();
		const output = new PassThrough();

		const promise = promptMaskedSecret("Key: ", input, output);
		input.end("first-line\nsecond-line\n");

		expect(await promise).toBe("first-line");
	});
});
