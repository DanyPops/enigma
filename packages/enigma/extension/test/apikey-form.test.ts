import { describe, expect, it } from "bun:test";
import { ApiKeyRegistrationForm, MaskedInput } from "../src/apikey-form.ts";

const NOOP_THEME = {
	label: (s: string) => s,
	focusedLabel: (s: string) => s,
	help: (s: string) => s,
	error: (s: string) => s,
};

const TAB = "\t";
const SHIFT_TAB = "\x1b[Z";
const ENTER = "\r";
const ESCAPE = "\x1b";
const BACKSPACE = "\x7f";

function type(target: { handleInput(data: string): void }, text: string): void {
	for (const ch of text) target.handleInput(ch);
}

describe("MaskedInput", () => {
	it("tracks the real value but never renders it -- only mask glyphs, one per character", () => {
		const input = new MaskedInput();
		type(input, "sk-secret");
		expect(input.getValue()).toBe("sk-secret");
		const rendered = input.render(80)[0] ?? "";
		expect(rendered).not.toContain("sk-secret");
		expect(rendered).toBe("•".repeat("sk-secret".length));
	});

	it("backspace removes the last character from the real value and shortens the mask", () => {
		const input = new MaskedInput();
		type(input, "abc");
		input.handleInput(BACKSPACE);
		expect(input.getValue()).toBe("ab");
		expect(input.render(80)[0]).toBe("••");
	});

	it("ignores escape sequences (e.g. arrow keys) instead of inserting them as characters", () => {
		const input = new MaskedInput();
		input.handleInput("\x1b[D"); // left arrow
		expect(input.getValue()).toBe("");
	});

	it("accepts a bracketed-paste sequence (Ctrl+V/Ctrl+Shift+V in most terminals) as one chunk, unlike a plain escape sequence", () => {
		const input = new MaskedInput();
		input.handleInput("\x1b[200~sk-pasted-secret-value\x1b[201~");
		expect(input.getValue()).toBe("sk-pasted-secret-value");
		expect(input.render(80)[0]).toBe("•".repeat("sk-pasted-secret-value".length));
	});

	it("buffers a bracketed paste split across multiple handleInput calls (a long paste arriving in several PTY chunks)", () => {
		const input = new MaskedInput();
		input.handleInput("\x1b[200~sk-pas");
		input.handleInput("ted-secre");
		input.handleInput("t-value\x1b[201~");
		expect(input.getValue()).toBe("sk-pasted-secret-value");
	});

	it("strips a trailing newline from a pasted value (common clipboard artifact) without corrupting the key", () => {
		const input = new MaskedInput();
		input.handleInput("\x1b[200~sk-secret\n\x1b[201~");
		expect(input.getValue()).toBe("sk-secret");
	});

	it("processes input typed immediately after a paste ends in the same chunk", () => {
		const input = new MaskedInput();
		input.handleInput("\x1b[200~pasted\x1b[201~typed");
		expect(input.getValue()).toBe("pastedtyped");
	});
});

describe("ApiKeyRegistrationForm", () => {
	it("starts focused on the name field and moves focus forward on Tab/Enter, backward on Shift+Tab", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME);
		type(form, "brave");
		form.handleInput(TAB); // -> env-var field
		type(form, "BRAVE_SEARCH_API_KEY");
		form.handleInput(SHIFT_TAB); // -> back to the name field
		type(form, "X"); // appended to the name field, proving Shift+Tab actually moved focus back
		form.handleInput(TAB); // -> env-var field
		form.handleInput(TAB); // -> value field
		type(form, "real-key");
		let result: unknown;
		form.onSubmit = (r) => { result = r; };
		form.handleInput(ENTER); // submit from the last field
		expect(result).toEqual({ name: "braveX", envVar: "BRAVE_SEARCH_API_KEY", value: "real-key" });
	});

	it("never renders the value field's real characters, even while focused on it", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME);
		form.handleInput(TAB);
		form.handleInput(TAB); // focus the value field
		type(form, "super-secret-value");
		const rendered = form.render(120).join("\n");
		expect(rendered).not.toContain("super-secret-value");
	});

	it("refuses to submit when any field is empty, and does not call onSubmit", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME);
		let called = false;
		form.onSubmit = () => { called = true; };
		form.handleInput(TAB);
		form.handleInput(TAB);
		form.handleInput(ENTER); // name and envVar still blank
		expect(called).toBe(false);
		expect(form.render(120).join("\n")).toContain("required");
	});

	it("calls onCancel on Escape from any field, without calling onSubmit", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME);
		let submitted = false;
		let canceled = false;
		form.onSubmit = () => { submitted = true; };
		form.onCancel = () => { canceled = true; };
		type(form, "brave");
		form.handleInput(ESCAPE);
		expect(canceled).toBe(true);
		expect(submitted).toBe(false);
	});

	it("pre-fills name/env-var defaults when constructed with them", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME, "brave", "BRAVE_SEARCH_API_KEY");
		form.handleInput(TAB);
		form.handleInput(TAB);
		type(form, "k");
		let result: unknown;
		form.onSubmit = (r) => { result = r; };
		form.handleInput(ENTER);
		expect(result).toEqual({ name: "brave", envVar: "BRAVE_SEARCH_API_KEY", value: "k" });
	});
});
