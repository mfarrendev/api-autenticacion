import type { IncomingMessage, ServerResponse } from "node:http";

export const LIMITE_CUERPO = 16 * 1024;

/**
 * Cabeceras en cada respuesta. Es una API JSON: no hay HTML que proteger con
 * una CSP fina, así que la CSP niega todo y prohíbe enmarcar.
 */
export const CABECERAS_SEGURIDAD: Record<string, string> = {
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store",
};

export class ErrorHttp extends Error {
  constructor(
    readonly estado: number,
    readonly codigo: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(codigo);
  }
}

export function responder(res: ServerResponse, estado: number, cuerpo: unknown, cabeceras: Record<string, string | string[]> = {}): void {
  const texto = cuerpo === undefined ? "" : JSON.stringify(cuerpo);
  res.writeHead(estado, {
    ...CABECERAS_SEGURIDAD,
    ...(texto ? { "Content-Type": "application/json; charset=utf-8" } : {}),
    ...cabeceras,
  });
  res.end(texto);
}

export async function leerJson(req: IncomingMessage): Promise<unknown> {
  const tipo = (req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
  // Exigir application/json también cierra el CSRF por formulario simple:
  // un <form> no puede mandar ese tipo sin pasar por una verificación CORS.
  if (tipo !== "application/json") throw new ErrorHttp(415, "tipo-no-soportado");
  const trozos: Buffer[] = [];
  let total = 0;
  for await (const t of req as AsyncIterable<Buffer>) {
    total += t.length;
    if (total > LIMITE_CUERPO) throw new ErrorHttp(413, "cuerpo-muy-grande");
    trozos.push(t);
  }
  try {
    return JSON.parse(Buffer.concat(trozos).toString("utf8") || "null");
  } catch {
    throw new ErrorHttp(400, "json-invalido");
  }
}

export function leerCookies(req: IncomingMessage): Map<string, string> {
  const m = new Map<string, string>();
  for (const par of (req.headers.cookie ?? "").split(";")) {
    const i = par.indexOf("=");
    if (i > 0) m.set(par.slice(0, i).trim(), par.slice(i + 1).trim());
  }
  return m;
}

/**
 * Prefijo __Host-: el navegador solo la acepta con Secure, sin Domain y con
 * Path=/, así que un subdominio no puede plantarla (fijación de sesión).
 */
export const COOKIE_SESION = "__Host-sid";

export function cookieSesion(valor: string, maxAgeS: number): string {
  return `${COOKIE_SESION}=${valor}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeS}`;
}

export function borrarCookieSesion(): string {
  return `${COOKIE_SESION}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

const METODOS_SEGUROS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * CSRF por verificación de origen (OWASP: "Verifying Origin With Standard
 * Headers"). Todo método que cambia estado debe traer un Origin de la lista;
 * si el navegador no lo manda, se acepta solo Sec-Fetch-Site: same-origin.
 * Sin ninguna de las dos, se rechaza: es preferible obligar a un cliente que
 * no es navegador a mandar Origin que dejar pasar una petición ciega.
 */
export function origenPermitido(req: IncomingMessage, permitidos: ReadonlySet<string>): boolean {
  if (METODOS_SEGUROS.has(req.method ?? "GET")) return true;
  const origen = req.headers.origin;
  if (typeof origen === "string") return permitidos.has(origen);
  return req.headers["sec-fetch-site"] === "same-origin";
}
