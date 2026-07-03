// End-to-end browser test for powd.
//
// Spawns a stub upstream and a real powd (../powd, build it first), loads
// a protected page in headless Chromium, lets the inline solver run, and
// asserts the reload lands on the upstream with a powd cookie set. Also
// captures light/dark screenshots of the interstitial.
//
// This is a development harness, not part of the Go build: see README.md.
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const powdBin = join(here, "..", "powd");
const upstreamPort = 18080;
const powdPort = 18081;
const base = `http://127.0.0.1:${powdPort}`;

if (!existsSync(powdBin)) {
  console.error("powd binary not found — run `make build` first");
  process.exit(1);
}

// --- Stub upstream -----------------------------------------------------
const upstream = createServer((req, res) => {
  res.end(`hello from upstream: ${req.url}`);
});
await new Promise((ok) => upstream.listen(upstreamPort, "127.0.0.1", ok));

// --- powd ---------------------------------------------------------------
const configPath = join(mkdtempSync(join(tmpdir(), "powd-e2e-")), "powd.toml");
writeFileSync(
  configPath,
  `listen = "127.0.0.1:${powdPort}"
upstream = "http://127.0.0.1:${upstreamPort}"
difficulty = 16
insecure_cookie = true
protect = ["/"]
exclude = ["/healthz"]
`
);
const powd = spawn(powdBin, ["-c", configPath], { stdio: ["ignore", "inherit", "inherit"] });

// Wait until powd proxies the excluded health path.
for (let i = 0; ; i++) {
  try {
    if ((await fetch(base + "/healthz")).ok) break;
  } catch {
    if (i > 50) {
      console.error("powd did not become ready");
      process.exit(1);
    }
    await new Promise((ok) => setTimeout(ok, 100));
  }
}

// --- Browser checks ------------------------------------------------------
const failures = [];
const check = (ok, msg) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failures.push(msg);
};

const browser = await chromium.launch();

// Full solve flow, light mode.
{
  const ctx = await browser.newContext({ viewport: { width: 800, height: 620 } });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => check(false, `page JS error: ${e.message}`));

  // Register the reload waiter before navigating: the solver can finish
  // fast enough that the 200 arrives before any code after goto() runs.
  const t0 = Date.now();
  const reloadedPromise = page.waitForResponse(
    (r) => r.url() === base + "/" && r.status() === 200,
    { timeout: 30000 }
  );
  const first = await page.goto(base + "/");
  check(first.status() === 403, "challenge page served with 403");
  const firstBody = await first.text();
  check(firstBody.includes('data-challenge="powd1.'), "challenge token embedded in page");
  check(firstBody.includes("Checking your browser"), "heading present");
  await page.screenshot({ path: join(here, "challenge-light.png") });

  const reloaded = await reloadedPromise;
  const solveMs = Date.now() - t0;
  check(reloaded.status() === 200, `page reloaded as 200 after solving (${solveMs} ms total)`);

  await page.waitForLoadState();
  check(
    (await page.textContent("body")).includes("hello from upstream: /"),
    "reloaded page shows upstream content"
  );

  const cookie = (await ctx.cookies()).find((c) => c.name === "powd");
  check(cookie !== undefined, "powd cookie set");
  check(cookie?.httpOnly === true, "cookie is HttpOnly");
  check(cookie?.sameSite === "Lax", "cookie is SameSite=Lax");

  // Second navigation must go straight through, no interstitial.
  const second = await page.goto(base + "/another/page");
  check(second.status() === 200, "second navigation skips the challenge");
  check(
    (await page.textContent("body")).includes("hello from upstream: /another/page"),
    "second page shows upstream content"
  );
  await ctx.close();
}

// Dark-mode rendering of the interstitial.
{
  const ctx = await browser.newContext({
    viewport: { width: 800, height: 620 },
    colorScheme: "dark",
  });
  const page = await ctx.newPage();
  // Hold the verify POST so the interstitial stays on screen.
  await page.route("**/.powd/verify", () => {});
  await page.goto(base + "/");
  await page.waitForTimeout(400); // let the progress bar advance a bit
  await page.screenshot({ path: join(here, "challenge-dark.png") });
  await ctx.close();
}

await browser.close();
powd.kill("SIGTERM");
upstream.close();

if (failures.length > 0) {
  console.error(`\n${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("\nall browser checks passed");
