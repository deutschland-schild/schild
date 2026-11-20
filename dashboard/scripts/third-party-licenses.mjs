// Collects the license texts of every installed production dependency of
// @schild/client-dashboard for THIRD_PARTY_LICENSES in the schild image and
// release tarball. Runs in the Dockerfile ui stage (no extra dependencies).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outFile = process.argv[2];
if (!outFile) {
  console.error("usage: node scripts/third-party-licenses.mjs <output-file>");
  process.exit(1);
}

const raw = execFileSync(
  "pnpm",
  ["--filter", "@schild/client-dashboard", "list", "--prod", "--json", "--depth", "Infinity"],
  { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }
);

const projects = JSON.parse(raw);
const seen = new Map();

function walk(deps) {
  if (!deps) return;
  for (const [name, info] of Object.entries(deps)) {
    if (
      info.path &&
      typeof info.version === "string" &&
      !info.version.startsWith("link:") &&
      fs.existsSync(info.path)
    ) {
      const key = `${name}@${info.version}`;
      if (!seen.has(key)) {
        seen.set(key, { name, version: info.version, dir: info.path });
      }
    }
    walk(info.dependencies);
  }
}

for (const project of projects) {
  walk(project.dependencies);
}

if (seen.size === 0) {
  console.error("no production dependencies found for @schild/client-dashboard");
  process.exit(1);
}

const sep = "=".repeat(78);
const chunks = [];

for (const key of [...seen.keys()].sort()) {
  const { name, version, dir } = seen.get(key);
  const files = fs
    .readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice|ofl)/i.test(f))
    .filter((f) => fs.statSync(path.join(dir, f)).isFile())
    .sort();

  if (files.length > 0) {
    for (const file of files) {
      const body = fs.readFileSync(path.join(dir, file), "utf8").trimEnd();
      chunks.push(`${sep}\nnpm:${name} ${version}: ${file}\n${sep}\n\n${body}\n`);
    }
    continue;
  }

  const pkgPath = path.join(dir, "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const lic = typeof pkg.license === "string" ? pkg.license : pkg.license?.type;
  if (!lic) {
    console.error(`no license file or package.json license field: ${name} ${version}`);
    process.exit(1);
  }
  const repo =
    typeof pkg.repository === "string"
      ? pkg.repository
      : pkg.repository?.url || pkg.homepage || "";
  const lines = [`License: ${lic}`];
  if (repo) lines.push(`Source: ${repo}`);
  chunks.push(`${sep}\nnpm:${name} ${version}: package.json\n${sep}\n\n${lines.join("\n")}\n`);
}

fs.writeFileSync(outFile, chunks.join("\n"), "utf8");
console.log(`wrote ${seen.size} frontend package licenses to ${outFile}`);
