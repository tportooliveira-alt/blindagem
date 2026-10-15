// build-rules.mjs — consolida as assinaturas derivadas pelos agentes num ruleset limpo.
// Valida cada regex, descarta invalida e ReDoS-lenta, deduplica, mapeia severidade.
// Uso: node scripts/build-rules.mjs <arquivo-resultado-do-workflow.json>
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const srcPath = process.argv[2];
if (!srcPath) { console.error("uso: node scripts/build-rules.mjs <workflow.json>"); process.exit(2); }

const root = JSON.parse(readFileSync(srcPath, "utf8"));
const data = root.result ?? root;
const raw = [];
for (const fam of data.familias ?? []) for (const s of fam.signatures ?? []) raw.push(s);
for (const e of data.extras ?? []) raw.push(e);

const SEV = { segredo: "critico", "chave-embutida": "critico", "config-perigosa": "alto",
  pii: "alto", "endpoint-interno": "medio", sourcemap: "medio", debug: "medio" };

const sample = ("abcDEF012_/+-.:=\"' " + "AKIAIOSFODNN7EXAMPLE sourceMappingURL=a.map service_role ").repeat(400);
const seen = new Set();
const ids = new Map();
const out = [];
let invalid = 0, slow = 0, dup = 0;

for (const s of raw) {
  if (!s || !s.regex) continue;
  if (seen.has(s.regex)) { dup++; continue; }
  let re;
  try { re = new RegExp(s.regex, "g"); } catch { invalid++; continue; }
  const t = Date.now();
  try { sample.replace(re, ""); } catch { invalid++; continue; }
  if (Date.now() - t > 60) { slow++; continue; }
  seen.add(s.regex);
  const classe = SEV[s.classe] ? s.classe : "segredo";
  let id = String(s.nome || "regra").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const n = (ids.get(id) ?? 0) + 1; ids.set(id, n); if (n > 1) id = `${id}-${n}`;
  out.push({ id, nome: s.nome || id, classe, severidade: SEV[classe], regex: s.regex });
}

const body = "// GERADO por scripts/build-rules.mjs — nao edite a mao. Regras hand-curated ficam em rules-extra.mjs.\n" +
  "export const RULES = [\n" +
  out.map(r => `  { id: ${JSON.stringify(r.id)}, nome: ${JSON.stringify(r.nome)}, classe: ${JSON.stringify(r.classe)}, severidade: ${JSON.stringify(r.severidade)}, re: new RegExp(${JSON.stringify(r.regex)}, "g") },`).join("\n") +
  "\n];\n";

mkdirSync(here + "/../src", { recursive: true });
writeFileSync(here + "/../src/rules.mjs", body, "utf8");
console.log(`regras: ${out.length} validas | ${dup} duplicadas | ${invalid} invalidas | ${slow} lentas(ReDoS) descartadas`);
const byClasse = {};
for (const r of out) byClasse[r.classe] = (byClasse[r.classe] || 0) + 1;
console.log("por classe:", JSON.stringify(byClasse));
