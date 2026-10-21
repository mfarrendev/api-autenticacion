import type { DatabaseSync } from "node:sqlite";
import type { Sesion } from "./db.ts";
import { hashSecreto, nuevoSecreto } from "./secretos.ts";

export interface PlazosSesion {
  /** Vida máxima desde el login, se use o no. */
  absolutoMs: number;
  /** Tiempo sin actividad tras el cual la sesión muere. */
  inactividadMs: number;
}

export function crearSesion(db: DatabaseSync, usuarioId: number, ahora: number): string {
  const id = nuevoSecreto();
  db.prepare("INSERT INTO sesiones (id_hash, usuario_id, creada, ultima_actividad) VALUES (?, ?, ?, ?)").run(
    hashSecreto(id),
    usuarioId,
    ahora,
    ahora,
  );
  return id;
}

/** Devuelve la sesión viva y renueva su actividad; borra la vencida. */
export function leerSesion(db: DatabaseSync, id: string, ahora: number, plazos: PlazosSesion): Sesion | null {
  const h = hashSecreto(id);
  const s = db.prepare("SELECT * FROM sesiones WHERE id_hash = ?").get(h) as Sesion | undefined;
  if (!s) return null;
  if (ahora - s.creada >= plazos.absolutoMs || ahora - s.ultima_actividad >= plazos.inactividadMs) {
    db.prepare("DELETE FROM sesiones WHERE id_hash = ?").run(h);
    return null;
  }
  db.prepare("UPDATE sesiones SET ultima_actividad = ? WHERE id_hash = ?").run(ahora, h);
  return { ...s, ultima_actividad: ahora };
}

export function cerrarSesion(db: DatabaseSync, id: string): void {
  db.prepare("DELETE FROM sesiones WHERE id_hash = ?").run(hashSecreto(id));
}

export function cerrarTodas(db: DatabaseSync, usuarioId: number): number {
  return Number(db.prepare("DELETE FROM sesiones WHERE usuario_id = ?").run(usuarioId).changes);
}
