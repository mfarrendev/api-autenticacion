import type { DatabaseSync } from "node:sqlite";

export interface ReglasBloqueo {
  /** Fallos tolerados antes del primer bloqueo. */
  umbral: number;
  /** Primer bloqueo; cada fallo siguiente lo duplica. */
  baseMs: number;
  techoMs: number;
  /** Sin fallos durante este lapso, el contador vuelve a cero. */
  olvidoMs: number;
}

interface Fila {
  fallos: number;
  ultimo: number;
  bloqueado_hasta: number;
}

/**
 * Bloqueo progresivo por clave ("cuenta:<correo>" o "ip:<dirección>").
 * Se cuenta por correo tecleado, exista o no la cuenta: si solo se bloquearan
 * las cuentas reales, el bloqueo mismo delataría cuáles existen.
 */
export function bloqueadoHasta(db: DatabaseSync, clave: string, ahora: number): number {
  const f = db.prepare("SELECT bloqueado_hasta FROM intentos WHERE clave = ?").get(clave) as Fila | undefined;
  return f && f.bloqueado_hasta > ahora ? f.bloqueado_hasta : 0;
}

export function registrarFallo(db: DatabaseSync, clave: string, ahora: number, r: ReglasBloqueo): void {
  const f = db.prepare("SELECT * FROM intentos WHERE clave = ?").get(clave) as Fila | undefined;
  const fallos = f && ahora - f.ultimo < r.olvidoMs ? f.fallos + 1 : 1;
  const exceso = fallos - r.umbral;
  const hasta = exceso >= 0 ? ahora + Math.min(r.techoMs, r.baseMs * 2 ** exceso) : 0;
  db.prepare(
    "INSERT INTO intentos (clave, fallos, ultimo, bloqueado_hasta) VALUES (?, ?, ?, ?) ON CONFLICT(clave) DO UPDATE SET fallos = excluded.fallos, ultimo = excluded.ultimo, bloqueado_hasta = excluded.bloqueado_hasta",
  ).run(clave, fallos, ahora, hasta);
}

export function limpiar(db: DatabaseSync, clave: string): void {
  db.prepare("DELETE FROM intentos WHERE clave = ?").run(clave);
}
