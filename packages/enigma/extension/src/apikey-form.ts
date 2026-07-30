/**
 * A three-field registration form for `enigma login apikey` from inside
 * pi's `/secrets` command: backend name, env var name, and the key value
 * itself -- the value field renders every keystroke as a mask glyph
 * instead of the real character, so a pasted/typed secret never appears
 * in the visible terminal transcript. `ctx.ui.input()` has no masked mode
 * at all (checked directly against its type -- ExtensionUIDialogOptions
 * carries only signal/timeout), which is why this needs a real custom
 * `ctx.ui.custom()` component rather than reusing the built-in dialog.
 */
import { type Component, Input, Key, matchesKey } from "@earendil-works/pi-tui";
import { MaskedInput } from "malevich-tui-components";

/**
 * Malevich's MaskedInput only ever asks its injected matcher about "backspace" --
 * ctrl+h was a separate, explicit alias in this form's own pre-Malevich copy, so
 * it's folded in here rather than dropped when delegating everything else to
 * pi-tui's real matchesKey.
 */
const matchesKeyWithCtrlHBackspace = (data: string, keyId: string): boolean =>
	keyId === "backspace" ? matchesKey(data, Key.backspace) || matchesKey(data, "ctrl+h") : matchesKey(data, keyId as Parameters<typeof matchesKey>[1]);

export interface ApiKeyFormResult {
	name: string;
	envVar: string;
	value: string;
}

export interface ApiKeyFormTheme {
	label: (s: string) => string;
	focusedLabel: (s: string) => string;
	help: (s: string) => string;
	error: (s: string) => string;
}

type Field = { label: string; input: Input | MaskedInput };

/**
 * Tab/Enter move to the next field (Enter on the last field submits);
 * Shift+Tab moves back; Escape cancels from anywhere. Submission is
 * refused, with an inline message rather than a call to onSubmit, when
 * any field is still empty -- the caller never sees a half-filled result.
 */
export class ApiKeyRegistrationForm implements Component {
	private readonly fields: Field[];
	private focusIndex = 0;
	private errorMessage: string | undefined;

	onSubmit?: (result: ApiKeyFormResult) => void;
	onCancel?: () => void;

	constructor(private readonly theme: ApiKeyFormTheme, defaultName = "", defaultEnvVar = "") {
		const nameInput = new Input();
		nameInput.setValue(defaultName);
		const envVarInput = new Input();
		envVarInput.setValue(defaultEnvVar);
		this.fields = [
			{ label: "Backend name", input: nameInput },
			{ label: "Env var name", input: envVarInput },
			{ label: "API key value", input: new MaskedInput({ matchesKey: matchesKeyWithCtrlHBackspace }) },
		];
	}

	handleInput(data: string): void {
		if (matchesKey(data, Key.escape)) {
			this.onCancel?.();
			return;
		}
		if (matchesKey(data, Key.shift("tab"))) {
			this.focusIndex = Math.max(0, this.focusIndex - 1);
			return;
		}
		if (matchesKey(data, Key.tab) || matchesKey(data, Key.enter)) {
			if (this.focusIndex < this.fields.length - 1) {
				this.focusIndex++;
			} else {
				this.trySubmit();
			}
			return;
		}
		this.fields[this.focusIndex]?.input.handleInput(data);
	}

	private trySubmit(): void {
		const name = (this.fields[0]?.input as Input).getValue().trim();
		const envVar = (this.fields[1]?.input as Input).getValue().trim();
		const value = (this.fields[2]?.input as MaskedInput).getValue();
		if (!name || !envVar || !value) {
			this.errorMessage = "All three fields are required.";
			return;
		}
		this.errorMessage = undefined;
		this.onSubmit?.({ name, envVar, value });
	}

	render(width: number): string[] {
		const lines: string[] = [];
		this.fields.forEach((field, i) => {
			const marker = i === this.focusIndex ? "> " : "  ";
			const prefix = `${marker}${field.label}: `;
			const rendered = field.input.render(Math.max(1, width - prefix.length))[0] ?? "";
			const styled = i === this.focusIndex ? this.theme.focusedLabel(prefix) : this.theme.label(prefix);
			lines.push(`${styled}${rendered}`);
		});
		if (this.errorMessage) lines.push(this.theme.error(this.errorMessage));
		lines.push(this.theme.help("tab/enter next field \u2022 shift+tab previous \u2022 enter on last field submits \u2022 esc cancel"));
		return lines;
	}

	invalidate(): void {}
}
