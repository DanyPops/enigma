#!/usr/bin/env bun
/**
 * Test fixture standing in for a real supervised daemon. Appends one line
 * per start (env var value + a start marker) to the log file given as
 * argv[2], so a test can observe multiple restarts across the same file.
 * If EXIT_CODE is set, exits with that code shortly after starting
 * (simulating a crash); otherwise runs until SIGTERM, exiting 0 — a real
 * graceful shutdown, not a forced kill, so supervisor.stop()'s contract is
 * actually exercised.
 */
import { appendFileSync } from "node:fs";

const logPath = process.argv[2];
if (!logPath) throw new Error("usage: fake-daemon.ts <log-path>");

const OBSERVED_VARS = ["PROBE_VALUE", "GITHUB_TOKEN", "GITLAB_TOKEN", "GITLAB_URL", "JENKINS_API_TOKEN", "JENKINS_USER", "JENKINS_URL", "JIRA_TOKEN"];
const observed = OBSERVED_VARS.map((name) => `${name}=${process.env[name] ?? ""}`).join(",");
appendFileSync(logPath, `start:${observed}\n`);

process.on("SIGTERM", () => {
	appendFileSync(logPath, "sigterm\n");
	process.exit(0);
});

if (process.env.EXIT_CODE !== undefined) {
	setTimeout(() => process.exit(Number(process.env.EXIT_CODE)), 30);
} else {
	setInterval(() => {}, 60_000); // keep the process alive until SIGTERM
}
