// scan.mjs — motor do Blindagem. Varre um arquivo/diretorio (inclui artefatos
// empacotados lidos como bytes) e devolve os vazamentos encontrados.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, basename, relative } from "node:path";
import { RULES } from "./rules.mjs";
import { EXTRA, FILENAME_RULES } from "./rules-extra.mjs";
import { hardeningFindings } from "./hardening.mjs";

const SKIP_DIR = new Set(["node_modules", ".git", ".hg", ".svn", ".cache"]);
// Corta falso-positivo em regras sensiveis: valor que e placeholder/ref de env, nao segredo real.
const PLACEHOLDER = /(process\.env|import\.meta\.env|os\.environ|getenv|example|exemplo|changeme|placeholder|dummy|your[-_ ]?|<[a-z][a-z0-9-]*>|\{\{|\$\{|xxxx+|redacted|\*\*\*\*)/i;
const MAX_BYTES = 64 * 1024 * 1024; // 64 MiB por arquivo
export const SEV_ORDER = { info: 0, medio: 1, alto: 2, critico: 3 };
const ALL = [...RULES, ...EXTRA];

function* walk(dir) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const name of entries) {
    if (SKIP_DIR.has(name)) continue;
    const p = join(dir, name);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p);
    else yield p;
  }
}

function redige(hit, classe) {
  if (classe === "segredo" || classe === "chave-embutida")
    return `<${classe}: ${hit.length} chars …${hit.slice(-4)}>`;
  if (classe === "pii") return hit.replace(/\d/g, "*");
  const one = hit.replace(/\s+/g, " ").trim();
  return one.length > 100 ? one.slice(0, 100) + "…" : one;
}

function ignored(f, ignore) {
  for (const pat of ignore) { if (f.rule === pat || f.file.includes(pat) || f.trecho.includes(pat)) return true; }
  return false;
}

export function scanPath(target, opts = {}) {
  const ignore = opts.ignore ?? [];
  const st = statSync(target);
  const files = st.isDirectory() ? [...walk(target)] : [target];
  const findings = [];
  const seen = new Set();
  const skipped = [];
  const add = (f) => {
    const k = `${f.file}|${f.rule}|${f.trecho}`;
    if (seen.has(k) || ignored(f, ignore)) return;
    seen.add(k); findings.push(f);
  };

  for (const f of files) {
    const rel = relative(process.cwd(), f) || f;
    const base = basename(f);
    for (const fr of FILENAME_RULES) {
      fr.re.lastIndex = 0;
      if (fr.re.test(base)) add({ rule: fr.id, nome: fr.nome, classe: fr.classe, severidade: fr.severidade, file: rel, trecho: base });
    }
    let buf; try { buf = readFileSync(f); } catch { continue; }
    if (!buf.length) continue;
    if (buf.length > MAX_BYTES) { skipped.push(rel); continue; }
    const text = buf.toString("latin1");
    for (const r of ALL) {
      r.re.lastIndex = 0;
      let m, count = 0;
      const global = r.re.global;
      while ((m = r.re.exec(text)) !== null) {
        const hit = m[0];
        const sensivel = r.classe === "segredo" || r.classe === "chave-embutida" || r.classe === "config-perigosa";
        if ((!r.validar || r.validar(hit)) && !(sensivel && PLACEHOLDER.test(hit))) {
          add({ rule: r.id, nome: r.nome, classe: r.classe, severidade: r.severidade, file: rel, trecho: redige(hit, r.classe) });
        }
        if (!global) break;
        if (++count >= 100) break;
        if (m.index === r.re.lastIndex) r.re.lastIndex++;
      }
    }
    for (const h of hardeningFindings(rel, text)) add(h);
  }
  findings.sort((a, b) => (SEV_ORDER[b.severidade] ?? 0) - (SEV_ORDER[a.severidade] ?? 0));
  return { findings, scanned: files.length, skipped, rules: ALL.length + FILENAME_RULES.length };
}

export function worst(findings) {
  return findings.reduce((w, f) => Math.max(w, SEV_ORDER[f.severidade] ?? 0), -1);
}
