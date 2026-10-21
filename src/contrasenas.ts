import { scrypt as scryptCb, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { CONTRASENAS_COMUNES } from "./comunes.ts";

const scrypt = promisify(scryptCb) as (
  clave: string | Buffer,
  sal: Buffer,
  largo: number,
  opciones: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/**
 * Parámetros de scrypt por versión. El hash guardado lleva su versión, así
 * que subir el costo no rompe a nadie: el que inicia sesión con un hash viejo
 * se verifica con sus parámetros y se re-hashea con los vigentes.
 * Nunca se edita una versión publicada: se agrega otra.
 */
export const PARAMETROS = {
  1: { N: 2 ** 14, r: 8, p: 1, largo: 32 },
  2: { N: 2 ** 15, r: 8, p: 1, largo: 32 },
} as const;
export type VersionHash = keyof typeof PARAMETROS;

export const LARGO_MINIMO = 12;
export const LARGO_MAXIMO = 128;

export type ProblemaContrasena = "muy-corta" | "muy-larga" | "comun" | "contiene-correo";

/** NFKC para que la misma clave tecleada en dos teclados dé el mismo hash. */
export function normalizar(clave: string): string {
  return clave.normalize("NFKC");
}

/**
 * Política NIST 800-63B: largo mínimo, máximo generoso, lista de comunes y
 * nada de reglas de composición (mayúscula, número, símbolo), que empujan a
 * claves predecibles como "Password1!". El largo se cuenta en puntos de
 * código, no en unidades UTF-16: un emoji es un carácter.
 */
export function revisarPolitica(clave: string, correo?: string): ProblemaContrasena | null {
  const n = normalizar(clave);
  const largo = [...n].length;
  if (largo < LARGO_MINIMO) return "muy-corta";
  if (largo > LARGO_MAXIMO) return "muy-larga";
  const minus = n.toLowerCase();
  if (CONTRASENAS_COMUNES.has(minus)) return "comun";
  if (correo) {
    const local = correo.split("@")[0]?.toLowerCase() ?? "";
    if (local.length >= 4 && minus.includes(local)) return "contiene-correo";
  }
  return null;
}

export async function hashear(clave: string, version: VersionHash): Promise<string> {
  const p = PARAMETROS[version];
  const sal = randomBytes(16);
  const h = await scrypt(normalizar(clave), sal, p.largo, { N: p.N, r: p.r, p: p.p, maxmem: 256 * p.N * p.r });
  return `scrypt$${version}$${sal.toString("base64url")}$${h.toString("base64url")}`;
}

export interface ResultadoVerificacion {
  valida: boolean;
  /** true si el hash está en una versión anterior y hay que re-hashear. */
  rehashear: boolean;
}

export async function verificar(clave: string, guardado: string, vigente: VersionHash): Promise<ResultadoVerificacion> {
  const partes = guardado.split("$");
  const version = Number(partes[1]) as VersionHash;
  const p = PARAMETROS[version];
  if (partes.length !== 4 || partes[0] !== "scrypt" || !p) return { valida: false, rehashear: false };
  const sal = Buffer.from(partes[2]!, "base64url");
  const esperado = Buffer.from(partes[3]!, "base64url");
  const h = await scrypt(normalizar(clave), sal, esperado.length, { N: p.N, r: p.r, p: p.p, maxmem: 256 * p.N * p.r });
  // Comparación en tiempo constante: no filtra cuántos bytes coincidieron.
  const valida = h.length === esperado.length && timingSafeEqual(h, esperado);
  return { valida, rehashear: valida && version < vigente };
}

let hashSenuelo: Promise<string> | null = null;
/**
 * Cuando el correo no existe se verifica igual contra un hash señuelo, para
 * que el tiempo de respuesta no delate si la cuenta existe.
 */
export async function verificarSenuelo(clave: string, vigente: VersionHash): Promise<void> {
  hashSenuelo ??= hashear(randomBytes(24).toString("base64url"), vigente);
  await verificar(clave, await hashSenuelo, vigente);
}
