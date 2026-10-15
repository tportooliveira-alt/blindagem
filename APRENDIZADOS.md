# Aprendizados — brechas achadas e corrigidas

> Diário do projeto. Toda vez que um teste pega uma brecha (falso-positivo, regra
> que não dispara, FP real), anota-se **onde foi** e **como fechou**. É o registro
> que faz o scanner melhorar a cada loop. Formato: data · o que · onde · correção.

## 2026-10-15

### [FP] regra genérica de credencial disparava em `process.env`
- **Onde:** `src/rules.mjs` regra `credencial-hardcoded-em-config`
  (`/(?:[Pp]ass(word|wd)|[Ss]ecret|[Aa]pi_?[Kk]ey)\s*[=:]\s*["']?[^\s"']{6,}/`),
  casando a linha limpa `const apiKey = process.env.API_KEY;` → match `apiKey = process.env.API_KEY;`.
- **Pego por:** `test/run.mjs` (fixture negativa deveria ter 0 achados, teve 1).
- **Correção:** guarda global de placeholder no motor (`src/scan.mjs`, `PLACEHOLDER`),
  aplicada a classes sensíveis (segredo / chave-embutida / config-perigosa):
  valor com `process.env`, `import.meta.env`, `example`, `${…}`, `your-`, `xxxx`,
  `<...>` etc. é referência/placeholder, não segredo real → não vira achado.
- **Resultado:** 204 ok, 0 falhou. A linha com segredo real
  (`api_key = "s3cr3t_v4lue_longo_aqui_123"`) continua disparando.

### [base] ruleset inicial consolidado
- 174 regras derivadas por agentes a partir dos alvos do REA (0 inválidas, 0 ReDoS),
  + 13 hand-curated (`src/rules-extra.mjs`, inclui cartão com Luhn, GCP/Azure/Twilio/SendGrid,
  atribuição genérica com guarda), + 7 por nome de arquivo (.env, id_rsa, *.pem, *.map, *.pdb…).
- Cobertura: segredo, chave-embutida, config-perigosa, pii, sourcemap, debug, endpoint-interno.

### [capacidade] blindagem ativa: impedir a RE automática, não só achar segredo
- **Motivo:** detectar vazamento não basta — a reversa fácil (a que o REA faz de graça)
  lê o código legível. A defesa tem que **exigir** ofuscação/strip.
- **Onde:** `src/hardening.mjs` (novo), integrado em `src/scan.mjs`.
- **O quê:** classe `blindagem-fraca` (severidade `medio`, bloqueia no `--fail-on=medio`):
  - `js-nao-ofuscado` — bundle JS indentado, nomes longos, sem assinatura de obfuscator → é fonte legível.
  - `nativo-com-simbolos` — binário com `.symtab`/`.debug_info` ou >20 símbolos C++ → não stripado.
- **Teste:** fixture legível dispara, ofuscada (`_0x…`) não, binário com símbolos dispara. 207 ok, 0 falhou.
- **Honestidade:** isto impede a RE **automática/casual** e encarece a manual; não torna impossível
  contra humano determinado — essa parte é server-side (ver método de blindagem).

## Como registrar um aprendizado novo
1. Escreva um teste em `test/run.mjs` que **reproduz** a brecha (fixture que deveria/não deveria disparar).
2. Rode `npm test` e confirme que ele **falha** (prova a brecha).
3. Corrija a regra (`src/rules-extra.mjs` para hand-curated; para as geradas, ajuste o derivador e regenere).
4. Rode `npm test` até **passar**.
5. Anote aqui: data, o que, onde, correção, resultado.
