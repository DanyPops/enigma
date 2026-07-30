import { describe, expect, it } from "bun:test";
import { ApiKeyRegistrationForm } from "../src/apikey-form.ts";

// MaskedInput itself is malevich-tui-components' own component now -- its generic
// behavior (paste handling, backspace, mask rendering) is covered by Malevich's
// own test suite, not duplicated here. This file keeps only enigma-specific
// behavior: the form wiring, and the ctrl+h backspace alias this form's own
// pre-Malevich copy explicitly supported (folded into a wrapped matchesKey,
// see apikey-form.ts).

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
const CTRL_H = "\x08";

function type(target: { handleInput(data: string): void }, text: string): void {
	for (const ch of text) target.handleInput(ch);
}

describe("ApiKeyRegistrationForm", () => {
	it("ctrl+h also removes the last character in the value field, preserving this form's pre-Malevich behavior", () => {
		const form = new ApiKeyRegistrationForm(NOOP_THEME, "brave", "BRAVE_SEARCH_API_KEY");
		form.handleInput(TAB);
		form.handleInput(TAB); // focus the value field
		type(form, "abc");
		form.handleInput(CTRL_H);
		let result: unknown;
		form.onSubmit = (r) => { result = r; };
		form.handleInput(ENTER);
		expect((result as { value: string }).value).toBe("ab");
	});

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
