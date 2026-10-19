// run.mjs — testa o motor de verdade: fixture positiva deve disparar, negativa nao,
// e regras especiais (Luhn, nome de arquivo) validadas. Sem dependencia.
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanPath } from "../src/scan.mjs";
import { RULES } from "../src/rules.mjs";
import { EXTRA, FILENAME_RULES } from "../src/rules-extra.mjs";

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; } else { fail++; console.log(`  FALHOU: ${msg}`); } };

// 1) toda regex e um RegExp valido (nao quebra no load)
for (const r of [...RULES, ...EXTRA]) ok(r.re instanceof RegExp, `regex invalida em ${r.id}`);
for (const r of FILENAME_RULES) ok(r.re instanceof RegExp, `filename regex invalida em ${r.id}`);

const dir = mkdtempSync(join(tmpdir(), "blindagem-test-"));
try {
  // 2) fixture POSITIVA — cada linha deve disparar alguma classe.
  // Tokens montados por concatenacao: o FONTE nao contem o padrao contiguo (nao
  // dispara o push-protection do GitHub), mas em runtime a string e completa e a
  // deteccao vale. Ironia util: o proprio repo nao pode vazar "segredo" de teste.
  const mk = (p, b) => p + b;
  const positivo = [
    `const a = "${mk("AKIA", "IOSFODNN7EXAMPLE")}";`,
    `const g = "${mk("AIza", "SyA1234567890abcdefghijklmnopqrstuv")}";`,
    `const s = "${mk("sk_live", "_0123456789abcdefghijklmno")}";`,
    `const gh = "${mk("ghp", "_0123456789abcdefghijklmnopqrstuvwxyz")}";`,
    `const oa = "${mk("sk-proj", "-0123456789abcdefghijklmnopqrstuvwxyz")}";`,
    '-----BEGIN PRIVATE KEY-----',
    '//# sourceMappingURL=app.js.map',
    'const u = "http://10.0.2.2:8080/admin";',
    'const cpf = "123.456.789-00";',
    'const card = "4111 1111 1111 1111";',               // Luhn valido
    'const api_key = "s3cr3t_v4lue_longo_aqui_123";',
    `const py = "${mk("pypi-", "AgEIcHlwaS5vcmc" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4")}";`,
    `CLOUDFLARE_API_TOKEN="${mk("v1A2b3C4d5E6f7G8h9I0", "j1K2l3M4n5O6p7Q8r9S0")}"`,
    `DD_API_KEY=${mk("0123456789", "abcdef0123456789abcdef")}`,
    `const nr = "${mk("NRAK-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0")}";`,
    `const gf = "${mk("glsa_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6")}_${mk("0123", "abcd")}";`,
    `const dp = "${mk("dp.pt.", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0")}";`,
  ].join("\n");
  writeFileSync(join(dir, "positivo.js"), positivo);

  // 3) fixture NEGATIVA — nada pode disparar
  const negativo = [
    'function soma(a, b) { return a + b; }',
    'const url = "https://api.minhaempresa.com/v1/users";',
    'const total = 1234567890123456;',                    // NAO passa Luhn -> nao e cartao
    'const nums = "100.200.300.40";',                     // nao e CPF
    'const apiKey = process.env.API_KEY;',                // placeholder -> ignorado
    'console.log("ola mundo");',
    'const t = process.env.CLOUDFLARE_API_TOKEN; // DD_API_KEY=your_key_here',
    'const pkg = "pypi-simple-index"; const nr = "NRAK-curto";',
  ].join("\n");
  writeFileSync(join(dir, "negativo.js"), negativo);

  // 4) fixtures por NOME DE ARQUIVO
  writeFileSync(join(dir, ".env"), "X=1");
  writeFileSync(join(dir, "id_rsa"), "x");
  writeFileSync(join(dir, "app.js.map"), "{}");

  const pos = scanPath(join(dir, "positivo.js")).findings;
  ok(pos.length >= 8, `positivo deveria ter >=8 achados, teve ${pos.length}`);
  for (const cls of ["segredo", "sourcemap", "endpoint-interno", "pii"])
    ok(pos.some((f) => f.classe === cls), `positivo sem classe ${cls}`);
  ok(pos.some((f) => f.rule === "cartao-credito"), "Luhn: cartao valido nao detectado");

  for (const rid of ["pypi-api-token", "cloudflare-api-token-atribuicao", "datadog-api-key-atribuicao", "newrelic-user-api-key", "grafana-service-account-token", "doppler-token"])
    ok(pos.some((f) => f.rule === rid), `regra nova ${rid} nao disparou`);

  const neg = scanPath(join(dir, "negativo.js")).findings;
  ok(neg.length === 0, `negativo deveria ter 0 achados, teve ${neg.length}: ${neg.map((f) => f.rule).join(",")}`);

  const whole = scanPath(dir).findings;
  for (const rid of ["arquivo-env", "ssh-id-rsa", "sourcemap-arquivo"])
    ok(whole.some((f) => f.rule === rid), `regra de nome de arquivo ${rid} nao disparou`);

  // 5) blindagem ativa — ausencia de ofuscacao/strip vira achado (impede RE facil)
  let legivel = "";
  for (let i = 0; i < 40; i++) legivel += `  function calcularValorTotalDaCompra_${i}(parametroInicial, taxaDeJurosMensal) {\n    const resultadoFinalCalculado = parametroInicial * taxaDeJurosMensal;\n    return resultadoFinalCalculado;\n  }\n`;
  writeFileSync(join(dir, "legivel.js"), legivel);
  writeFileSync(join(dir, "ofuscado.js"), "const _0x1a2b=['log','info'];function _0x3c4d(a,b){return _0x1a2b[a]}" + "\n".repeat(0) + "x".repeat(1100));
  writeFileSync(join(dir, "binario.so"), ".symtab\0_ZN3app4mainEv _ZN3app6helperEv _ZN3app4initEv " + "_ZN3lib3fooEv ".repeat(25));

  ok(scanPath(join(dir, "legivel.js")).findings.some((f) => f.rule === "js-nao-ofuscado"), "js legível não foi flagado como blindagem-fraca");
  ok(!scanPath(join(dir, "ofuscado.js")).findings.some((f) => f.rule === "js-nao-ofuscado"), "js ofuscado foi flagado por engano");
  ok(scanPath(join(dir, "binario.so")).findings.some((f) => f.rule === "nativo-com-simbolos"), "binário com símbolos não foi flagado");

} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} ok, ${fail} falhou  (${RULES.length}+${EXTRA.length} regras de conteudo, ${FILENAME_RULES.length} de nome)`);
process.exit(fail ? 1 : 0);
