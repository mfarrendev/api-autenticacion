import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

export type EventoAuditoria =
  | "registro"
  | "registro-repetido"
  | "correo-verificado"
  | "login-ok"
  | "login-fallido"
  | "login-bloqueado"
  | "login-sin-verificar"
  | "rehash"
  | "logout"
  | "logout-todas"
  | "recuperacion-pedida"
  | "recuperacion-usada"
  | "token-invalido"
  | "csrf-rechazado"
  | "acceso-denegado";

/**
 * Detalle permitido: solo claves de esta lista. Así una llamada descuidada
 * no puede meter la contraseña ni un token en la bitácora: el campo se
 * descarta antes de escribir.
 */
const CLAVES_PERMITIDAS = new Set(["correo_huella", "motivo", "ruta", "recurso", "sesiones_cerradas", "version"]);

/** Huella corta del correo: permite correlacionar fallos sin guardar lo tecleado. */
export function huellaCorreo(correo: string): string {
  return createHash("sha256").update(correo.trim().toLowerCase()).digest("hex").slice(0, 16);
}

export function auditar(
  db: DatabaseSync,
  fecha: number,
  evento: EventoAuditoria,
  datos: { usuarioId?: number | null; ip?: string | null; detalle?: Record<string, string | number> } = {},
): void {
  const detalle: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(datos.detalle ?? {})) if (CLAVES_PERMITIDAS.has(k)) detalle[k] = v;
  db.prepare("INSERT INTO auditoria (fecha, evento, usuario_id, ip, detalle) VALUES (?, ?, ?, ?, ?)").run(
    fecha,
    evento,
    datos.usuarioId ?? null,
    datos.ip ?? null,
    JSON.stringify(detalle),
  );
}
