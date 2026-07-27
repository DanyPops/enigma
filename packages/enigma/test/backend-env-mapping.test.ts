import { describe, expect, it } from "bun:test";
import { defaultEnvVarName } from "../src/backend-env-mapping.ts";

describe("defaultEnvVarName", () => {
	it("uppercases and sanitizes an arbitrary backend name into a _TOKEN suffixed var name", () => {
		expect(defaultEnvVarName("my-company-sso")).toBe("MY_COMPANY_SSO_TOKEN");
		expect(defaultEnvVarName("weird.name!!")).toBe("WEIRD_NAME_TOKEN");
		expect(defaultEnvVarName("--leading-trailing--")).toBe("LEADING_TRAILING_TOKEN");
	});
});
