// hardening.mjs — nao procura segredo: procura AUSENCIA de blindagem ativa.
// Impede a engenharia reversa AUTOMATICA/facil (a que o REA faz de graca):
// codigo legivel vira "blindagem-fraca" e bloqueia o release ate ofuscar/stripar.
import { extname } from "node:path";

const JS = new Set([".js", ".mjs", ".cjs"]);
const NATIVO = new Set([".exe", ".dll", ".so", ".dylib", ".node", ".o", ".a"]);

export function hardeningFindings(file, text) {
  const ext = extname(file).toLowerCase();
  const out = [];

  // JS/Electron/Web: bundle de producao legivel = RE le o codigo direto.
  if (JS.has(ext) && text.length > 1024) {
    const ofuscado = /_0x[0-9a-f]{4,}/.test(text) || /\b[a-z]\d?\[\d+\]\[\d+\]/.test(text);
    if (!ofuscado) {
      const lines = text.split("\n");
      const avg = text.length / lines.length;
      let indent = 0;
      for (const l of lines) if (/^[\t ]{2,}\S/.test(l)) indent++;
      const indentRatio = indent / lines.length;
      const longIdents = (text.match(/[A-Za-z_$][A-Za-z0-9_$]{6,}/g) || []).length;
      if (indentRatio > 0.15 && avg < 300 && longIdents > 30) {
        out.push({ rule: "js-nao-ofuscado", nome: "JS legível (não ofuscado/minificado)", classe: "blindagem-fraca", severidade: "medio", file, trecho: `linha_média=${Math.round(avg)} indentação=${(indentRatio * 100) | 0}% nomes_longos=${longIdents} → ofusque (javascript-obfuscator) e minifique` });
      }
    }
  }

  // Nativo: binario com tabela de simbolos / nomes C++ legiveis = nao foi stripado.
  if (NATIVO.has(ext)) {
    const mangled = (text.match(/_Z[NL]?[0-9A-Za-z_]{4,}/g) || []).length;
    const temSimbolos = text.includes(".symtab") || text.includes(".debug_info");
    if (temSimbolos || mangled > 20) {
      out.push({ rule: "nativo-com-simbolos", nome: "binário não stripado (símbolos legíveis)", classe: "blindagem-fraca", severidade: "medio", file, trecho: temSimbolos ? "seção .symtab/.debug_info presente → strip -s" : `${mangled} símbolos C++ legíveis → strip -s e visibilidade oculta` });
    }
  }

  return out;
}
