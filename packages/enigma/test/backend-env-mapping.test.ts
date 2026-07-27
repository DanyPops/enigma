import { describe, expect, it } from "bun:test";
import { defaultEnvVarName, normalizeBackendName } from "../src/backend-env-mapping.ts";

describe("normalizeBackendName", () => {
	it("lowercases so a backend name is one consistent lookup key regardless of the casing it was typed with", () => {
		expect(normalizeBackendName("WidgetApi")).toBe("widgetapi");
		expect(normalizeBackendName("widgetapi")).toBe("widgetapi");
		expect(normalizeBackendName("WIDGETAPI")).toBe("widgetapi");
	});
});

describe("defaultEnvVarName", () => {
	it("uppercases and sanitizes an arbitrary backend name into a _TOKEN suffixed var name", () => {
		expect(defaultEnvVarName("my-company-sso")).toBe("MY_COMPANY_SSO_TOKEN");
		expect(defaultEnvVarName("weird.name!!")).toBe("WEIRD_NAME_TOKEN");
		expect(defaultEnvVarName("--leading-trailing--")).toBe("LEADING_TRAILING_TOKEN");
	});
});
