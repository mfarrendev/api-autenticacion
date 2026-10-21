import { createHash, randomBytes } from "node:crypto";

/** 256 bits de azar: el identificador de sesión o el token que viaja al usuario. */
export function nuevoSecreto(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Lo que se guarda en la base. SHA-256 sin sal basta: el secreto ya tiene
 * 256 bits de entropía y no hay diccionario que recorrer, a diferencia de
 * una contraseña.
 */
export function hashSecreto(secreto: string): string {
  return createHash("sha256").update(secreto).digest("hex");
}
