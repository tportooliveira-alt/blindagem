// rules-extra.mjs — regras HAND-CURATED de alta confianca (editaveis a mao).
// Complementam as geradas em rules.mjs. Entradas podem ter validar(hit) para cortar falso positivo.

function luhn(num) {
  const d = num.replace(/[^0-9]/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

const PLACEHOLDER = /(example|exemplo|xxxx+|your[-_]?|changeme|placeholder|dummy|test[-_]?key|process\.env|import\.meta\.env|\$\{|<[a-z])/i;

export const EXTRA = [
  { id: "cartao-credito", nome: "numero de cartao (Luhn)", classe: "pii", severidade: "critico",
    re: /\b(?:\d[ -]?){13,19}\b/g, validar: (h) => luhn(h) },
  { id: "cnpj", nome: "CNPJ", classe: "pii", severidade: "alto",
    re: /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g },
  { id: "aws-secret-access-key", nome: "AWS secret access key (atribuicao)", classe: "segredo", severidade: "critico",
    re: /aws_secret_access_key["']?\s*[:=]\s*["'][A-Za-z0-9/+]{40}["']/gi, validar: (h) => !PLACEHOLDER.test(h) },
  { id: "gcp-service-account-privkey", nome: "GCP service account private_key", classe: "chave-embutida", severidade: "critico",
    re: /"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { id: "azure-storage-key", nome: "Azure Storage AccountKey", classe: "segredo", severidade: "critico",
    re: /AccountKey\s*=\s*[A-Za-z0-9/+]{80,}={0,2}/g },
  { id: "twilio-account-sid", nome: "Twilio Account SID", classe: "segredo", severidade: "alto",
    re: /\bAC[0-9a-fA-F]{32}\b/g },
  { id: "sendgrid-key", nome: "SendGrid API key", classe: "segredo", severidade: "critico",
    re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g },
  { id: "digitalocean-token", nome: "DigitalOcean token", classe: "segredo", severidade: "critico",
    re: /\bdop_v1_[a-f0-9]{64}\b/g },
  { id: "anthropic-key", nome: "Anthropic API key", classe: "segredo", severidade: "critico",
    re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  { id: "authorization-bearer-hardcoded", nome: "Authorization Bearer hardcoded", classe: "segredo", severidade: "alto",
    re: /Authorization["']?\s*[:=]\s*["']Bearer\s+[A-Za-z0-9._\-]{16,}["']/gi, validar: (h) => !PLACEHOLDER.test(h) },
  { id: "segredo-atribuicao-generico", nome: "segredo em atribuicao (generico)", classe: "segredo", severidade: "alto",
    re: /\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|access[_-]?key)["']?\s*[:=]\s*["'][^"'\s]{12,}["']/gi,
    validar: (h) => !PLACEHOLDER.test(h) },
  { id: "rustc-commit-path", nome: "caminho /rustc/<hash> (debug)", classe: "debug", severidade: "medio",
    re: /\/rustc\/[0-9a-f]{40}\//g },
  { id: "sourcescontent-inline", nome: "sourcesContent embutido (fonte original)", classe: "sourcemap", severidade: "alto",
    re: /"sourcesContent"\s*:\s*\[/g },
];

// Regras por NOME DE ARQUIVO (casam contra o basename, nao o conteudo).
export const FILENAME_RULES = [
  { id: "arquivo-env", nome: ".env no artefato", classe: "config-perigosa", severidade: "critico", re: /^\.env(\.[A-Za-z0-9]+)?$/ },
  { id: "chave-privada-arquivo", nome: "arquivo de chave privada", classe: "chave-embutida", severidade: "critico", re: /\.(pem|key|p12|pfx|jks|keystore|ppk)$/i },
  { id: "ssh-id-rsa", nome: "chave SSH (id_rsa)", classe: "chave-embutida", severidade: "critico", re: /^id_(rsa|dsa|ecdsa|ed25519)$/ },
  { id: "sourcemap-arquivo", nome: "source map publicado", classe: "sourcemap", severidade: "medio", re: /\.(js|mjs|cjs|css)\.map$/i },
  { id: "pdb-arquivo", nome: "simbolo de debug (.pdb)", classe: "debug", severidade: "medio", re: /\.pdb$/i },
  { id: "mobileprovision", nome: "perfil de provisionamento Apple", classe: "config-perigosa", severidade: "alto", re: /\.mobileprovision$/i },
  { id: "captura-vazada", nome: "captura de trafego no artefato", classe: "config-perigosa", severidade: "alto", re: /\.(har|saz|pcap|pcapng|mitm)$/i },
];
