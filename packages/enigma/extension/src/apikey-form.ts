/**
 * A three-field registration form for `enigma login apikey` from inside
 * pi's `/secrets` command: backend name, env var name, and the key value
 * itself -- the value field renders every keystroke as a mask glyph
 * instead of the real character, so a pasted/typed secret never appears
 * in the visible terminal transcript. `ctx.ui.input()` has no masked mode
 * at all (checked directly against its type -- ExtensionUIDialogOptions
 * carries only signal/timeout), which is why this needs a real custom
 * `ctx.ui.custom()` component rather than reusing the built-in dialog.
 *
 * Thin wrapper around Malevich's generic Form + MaskedInput -- this file
 * used to hand-roll its own focus/navigation/validation loop identical to
 * what Form now owns generically (see the sibling Papyrus migration task).
 * Behavior is unchanged: same field order, same key handling, same
 * pre-Malevich ctrl+h backspace alias, same help text (Form's own default
 * literally matches the string this form used before).
 */
import { type Component, Input, Key, type KeyId, matchesKey } from "@earendil-works/pi-tui";
import { Form, type FormTheme, type KeyMatcher, MaskedInput } from "malevich-tui-components";

/**
 * Malevich's MaskedInput/Form only ever ask this matcher about "backspace" --
 * ctrl+h was a separate, explicit alias in this form's own pre-Malevich copy, so
 * it's folded in here rather than dropped when delegating everything else to
 * pi-tui's real matchesKey.
 */
const matchesKeyWithCtrlHBackspace: KeyMatcher = (data, keyId) =>
	keyId === "backspace" ? matchesKey(data, Key.backspace) || matchesKey(data, "ctrl+h") : matchesKey(data, keyId as KeyId);

export interface ApiKeyFormResult {
	name: string;
	envVar: string;
	value: string;
}

export type ApiKeyFormTheme = FormTheme;

/**
 * Tab/Enter move to the next field (Enter on the last field submits);
 * Shift+Tab moves back; Escape cancels from anywhere. Submission is
 * refused, with an inline message rather than a call to onSubmit, when
 * any field is still empty -- the caller never sees a half-filled result.
 */
export class ApiKeyRegistrationForm implements Component {
	private readonly form: Form;

	onSubmit?: (result: ApiKeyFormResult) => void;
	onCancel?: () => void;

	constructor(theme: ApiKeyFormTheme, defaultName = "", defaultEnvVar = "") {
		const nameInput = new Input();
		nameInput.setValue(defaultName);
		const envVarInput = new Input();
		envVarInput.setValue(defaultEnvVar);
		this.form = new Form({
			theme,
			matchesKey: matchesKeyWithCtrlHBackspace,
			fields: [
				{ key: "name", label: "Backend name", input: nameInput },
				{ key: "envVar", label: "Env var name", input: envVarInput },
				{ key: "value", label: "API key value", input: new MaskedInput({ matchesKey: matchesKeyWithCtrlHBackspace }) },
			],
		});
		this.form.onSubmit = (result) => this.onSubmit?.({ name: result.name ?? "", envVar: result.envVar ?? "", value: result.value ?? "" });
		this.form.onCancel = () => this.onCancel?.();
	}

	handleInput(data: string): void {
		this.form.handleInput(data);
	}

	render(width: number): string[] {
		return this.form.render(width);
	}

	invalidate(): void {
		this.form.invalidate();
	}
}
