# Blindagem 🛡️

**Antivírus de cópia** — scanner de vazamento que a empresa roda no **próprio** software, antes de lançar, para não entregar segredo a quem faz engenharia reversa.
*Anti-copy / anti-reverse-engineering leak scanner you run on your own build before shipping.*

> A verdade que organiza tudo: ferramentas de engenharia reversa (Ghidra, Hopper, IDA, e as de JS/Electron/Android) **leem tudo que você entrega** — binário, bundle, APK, ASAR. Criptografar o cliente não esconde nada: a chave vai junto. Então a defesa não é esconder; é **não embarcar o que não pode vazar** e **provar isso a cada release**. O Blindagem é a prova automatizada.

## O que ele acha

7 classes de vazamento, **~194 regras** (174 derivadas dos alvos de RE + 13 hand-curated + 7 por nome de arquivo):

| Classe | Exemplos |
|---|---|
| `segredo` | AWS, Google, Stripe, Slack, GitHub, OpenAI/Anthropic, npm, Twilio, SendGrid, Azure, DigitalOcean |
| `chave-embutida` | chave privada PEM, service account GCP, JWT/`service_role` Supabase |
| `config-perigosa` | `.env` no pacote, `debug=true`, `allowBackup=true`, `service_role` exposto |
| `pii` | CPF, CNPJ, cartão de crédito (validado por Luhn) |
| `sourcemap` | `.map` publicado, `sourceMappingURL`, `sourcesContent` embutido |
| `debug` | `.pdb`, `.dSYM`, DWARF, `/rustc/<hash>/` |
| `endpoint-interno` | `localhost`, IP privado, `staging.`/`admin.`/`internal.` |
| `blindagem-fraca` | **ausência de proteção ativa**: JS não ofuscado, binário não stripado — bloqueia a RE fácil |

Lê inclusive **artefatos empacotados** (`.asar`, `.exe`, `.so`, `.wasm`…) como bytes — é assim que um RE extrai strings.

## Uso

```bash
# diretório do build publicável, um arquivo, ou um pacote
node bin/blindagem.mjs ./dist
node bin/blindagem.mjs app.asar
node bin/blindagem.mjs ./dist --fail-on=alto --json
```

Sai **0 = LIBERADO (pode lançar)**, **1 = BLOQUEADO**. É o portão de release: coloque no CI (`.github/workflows/ci.yml`) e o build falha se vazar.

```bash
npm test     # roda a suíte (fixture positiva dispara, negativa não, Luhn, nomes de arquivo)
```

## Por que não é "só mais um gitleaks"

gitleaks (~140 regras) e TruffleHog (800+ detectores) são ótimos e **complementares** — use junto. O diferencial do Blindagem é o **enquadramento anti-engenharia-reversa**: as regras foram derivadas do que um RE extrai de **cada tipo de alvo** (JS/Electron, Android, Flutter, .NET, nativo, WASM, firmware, EVM…), e vêm com o **método de blindagem por alvo** e o **portão de release**. Não é caça-segredo-no-git; é **prova de que o artefato que vai pro usuário não entrega poder a ninguém**.

## Aprende a cada loop

Toda brecha que um teste pega é anotada em [`APRENDIZADOS.md`](APRENDIZADOS.md) (o quê, **onde foi**, como fechou) e vira regra/guarda nova. O ruleset cresce em `src/rules-extra.mjs` (hand-curated) e `src/rules.mjs` (geradas).

## Honestidade (o que ele NÃO faz)

- Não impede engenharia reversa — **código legível é irredutível**; a defesa disso é mover a lógica pro servidor.
- Não substitui autorização no servidor (IDOR/RLS), versão mínima de cliente nem rotação de segredo — isso é processo, não scanner. Veja o método completo nos docs de blindagem.
- Regex tem limite: confirme segredo achado antes de agir, e rode também gitleaks/TruffleHog para cobertura máxima.

## Licença

MIT © Thiago Porto Oliveira
