#!/usr/bin/env node
// Blindagem — antivírus de cópia / anti-reverse-engineering para o SEU próprio software.
// Roda no artefato publicável antes de lançar e bloqueia o release se achar vazamento.
import { existsSync, readFileSync } from "node:fs";
import { scanPath, worst, SEV_ORDER } from "../src/scan.mjs";

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith("--")));
const pos = argv.filter((a) => !a.startsWith("--"));
const target = pos[0];
const getOpt = (name, def) => { const p = `--${name}=`; const a = argv.find((x) => x.startsWith(p)); return a ? a.slice(p.length) : def; };

if (!target || flags.has("--help")) {
  console.log(`Blindagem — scanner de vazamento anti-cópia / anti-RE

uso:  blindagem <arquivo-ou-dir> [opcoes]

  --json              saida em JSON
  --fail-on=<sev>     bloqueia a partir de: info|medio|alto|critico (padrao: medio)
  --ignore=<arquivo>  lista (uma por linha) de id de regra ou trecho a ignorar
  --quiet             so o resultado final

exit 0 = LIBERADO (pode lancar) | 1 = BLOQUEADO | 2 = uso errado`);
  process.exit(target ? 0 : 2);
}
if (!existsSync(target)) { console.error(`alvo nao existe: ${target}`); process.exit(2); }

const failOn = getOpt("fail-on", "medio");
if (!(failOn in SEV_ORDER)) { console.error(`--fail-on invalido: ${failOn}`); process.exit(2); }
let ignore = [];
const ignFile = getOpt("ignore");
if (ignFile && existsSync(ignFile)) ignore = readFileSync(ignFile, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));

const { findings, scanned, skipped, rules } = scanPath(target, { ignore });
const quiet = flags.has("--quiet");

if (flags.has("--json")) {
  console.log(JSON.stringify({ target, scanned, rules, skipped, findings, bloqueado: worst(findings) >= SEV_ORDER[failOn] }, null, 2));
} else {
  if (!quiet) console.log(`\nBlindagem — ${scanned} arquivo(s), ${rules} regras, alvo: ${target}\n`);
  if (findings.length === 0) console.log("Nenhum vazamento encontrado.");
  else {
    const byClasse = {};
    for (const f of findings) (byClasse[f.classe] ??= []).push(f);
    for (const [classe, list] of Object.entries(byClasse)) {
      console.log(`[${classe}] ${list.length}:`);
      for (const f of list.slice(0, 40)) console.log(`   ${f.severidade.toUpperCase().padEnd(7)} ${f.nome}  ${f.file}  → ${f.trecho}`);
      if (list.length > 40) console.log(`   … +${list.length - 40}`);
    }
  }
  if (skipped.length) console.log(`\n(${skipped.length} arquivo(s) grandes pulados)`);
}

const blocked = worst(findings) >= SEV_ORDER[failOn];
if (!flags.has("--json")) console.log(blocked ? `\nRESULTADO: BLOQUEADO (>= ${failOn}) — nao lancar.\n` : `\nRESULTADO: LIBERADO — pode lancar.\n`);
process.exit(blocked ? 1 : 0);
