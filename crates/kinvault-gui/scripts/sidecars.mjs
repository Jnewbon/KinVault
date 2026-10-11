// Builds kinvaultd and the kinvault CLI and puts them where Tauri's
// `externalBin` expects them (binaries/<name>-<target triple>[.exe]), so the
// bundle installs them next to the app, where the app looks for kinvaultd.
// Run by `tauri build` via tauri.bundle.conf.json.
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const appDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const workspace = join(appDir, "..", "..");
const run = (cmd, args) => execFileSync(cmd, args, { cwd: workspace, encoding: "utf8" });

const host = run("rustc", ["-vV"]).match(/^host: (.+)$/m)[1];
const triple = process.env.TAURI_ENV_TARGET_TRIPLE || host;
const debug = process.env.TAURI_ENV_DEBUG === "true";

const args = ["build", "-p", "kinvault-daemon", "-p", "kinvault-cli"];
if (!debug) args.push("--release");
if (triple !== host) args.push("--target", triple);
execFileSync("cargo", args, { cwd: workspace, stdio: "inherit" });

const targetDir = JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--no-deps"])).target_directory;
const outDir = join(targetDir, triple === host ? "" : triple, debug ? "debug" : "release");
const exe = triple.includes("windows") ? ".exe" : "";
mkdirSync(join(appDir, "binaries"), { recursive: true });
for (const name of ["kinvaultd", "kinvault"]) {
  const dest = join(appDir, "binaries", `${name}-${triple}${exe}`);
  copyFileSync(join(outDir, name + exe), dest);
  chmodSync(dest, 0o755);
  console.log(`sidecar ready: ${dest}`);
}
