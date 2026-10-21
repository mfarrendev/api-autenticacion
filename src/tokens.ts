import type { DatabaseSync } from "node:sqlite";
import { hashSecreto, nuevoSecreto } from "./secretos.ts";

export type TipoToken = "recuperar" | "verificar";

export function emitirToken(db: DatabaseSync, usuarioId: number, tipo: TipoToken, ahora: number, vigenciaMs: number): string {
  // Un token nuevo anula los anteriores del mismo tipo: solo vale el último correo.
  db.prepare("DELETE FROM tokens WHERE usuario_id = ? AND tipo = ?").run(usuarioId, tipo);
  const t = nuevoSecreto();
  db.prepare("INSERT INTO tokens (hash, usuario_id, tipo, vence) VALUES (?, ?, ?, ?)").run(hashSecreto(t), usuarioId, tipo, ahora + vigenciaMs);
  return t;
}

/**
 * Consume el token de forma atómica: el UPDATE solo marca uno que no esté
 * usado ni vencido, así que dos peticiones simultáneas con el mismo token no
 * pueden ganar las dos.
 */
export function consumirToken(db: DatabaseSync, token: string, tipo: TipoToken, ahora: number): number | null {
  const fila = db
    .prepare("UPDATE tokens SET usado = 1 WHERE hash = ? AND tipo = ? AND usado = 0 AND vence > ? RETURNING usuario_id")
    .get(hashSecreto(token), tipo, ahora) as { usuario_id: number } | undefined;
  return fila?.usuario_id ?? null;
}
