import type { Server } from "node:http";
import { configPorOmision, type Config } from "../src/app.ts";
import { CorreoMemoria } from "../src/correo.ts";
import { abrirBase } from "../src/db.ts";
import { levantar } from "../src/servidor.ts";

export const ORIGEN = "https://app.ejemplo.test";
export const CLAVE = "caballo bateria grapa correcta";

export interface Entorno {
  url: string;
  correo: CorreoMemoria;
  cfg: Config;
  reloj: { t: number; avanzar(ms: number): void };
  cerrar(): Promise<void>;
}

/** Servidor real en un puerto efímero, con base en memoria y reloj manual. */
export async function entorno(ajustes: Partial<Config> = {}): Promise<Entorno> {
  const reloj = { t: Date.UTC(2026, 0, 1), avanzar(ms: number) { this.t += ms; } };
  const correo = new CorreoMemoria();
  const cfg = configPorOmision({ db: abrirBase(), correo, origenes: [ORIGEN], urlPublica: ORIGEN, ahora: () => reloj.t, ...ajustes });
  const { servidor, url } = await levantar(cfg);
  return { url, correo, cfg, reloj, cerrar: () => cerrarServidor(servidor) };
}

function cerrarServidor(s: Server): Promise<void> {
  s.closeAllConnections();
  return new Promise((ok) => s.close(() => ok()));
}

export interface Respuesta {
  estado: number;
  cuerpo: any;
  cabeceras: Headers;
  setCookie: string[];
}

/** Un navegador mínimo: guarda la cookie de sesión y manda Origin por omisión. */
export class Navegador {
  cookie: string | null = null;
  constructor(private readonly url: string) {}

  async pedir(metodo: string, ruta: string, cuerpo?: unknown, cabeceras: Record<string, string> = {}): Promise<Respuesta> {
    const h: Record<string, string> = { Origin: ORIGEN, ...cabeceras };
    if (cuerpo !== undefined && !("Content-Type" in h)) h["Content-Type"] = "application/json";
    if (this.cookie) h.Cookie = this.cookie;
    for (const [k, v] of Object.entries(h)) if (v === "") delete h[k];
    const r = await fetch(this.url + ruta, {
      method: metodo,
      headers: h,
      body: cuerpo === undefined ? undefined : typeof cuerpo === "string" ? cuerpo : JSON.stringify(cuerpo),
    });
    const setCookie = r.headers.getSetCookie();
    for (const c of setCookie) {
      const [par] = c.split(";");
      const [nombre, valor] = par!.split("=");
      if (nombre === "__Host-sid") this.cookie = valor ? `${nombre}=${valor}` : null;
    }
    const texto = await r.text();
    return { estado: r.status, cuerpo: texto ? JSON.parse(texto) : null, cabeceras: r.headers, setCookie };
  }
}

export function tokenDe(texto: string): string {
  const m = texto.match(/#([A-Za-z0-9_-]{43})/);
  if (!m) throw new Error("el correo no trae token");
  return m[1]!;
}

/** Registra, verifica y deja al navegador con sesión iniciada. */
export async function usuarioListo(e: Entorno, correo: string, clave = CLAVE): Promise<Navegador> {
  const n = new Navegador(e.url);
  const r = await n.pedir("POST", "/auth/registro", { correo, contrasena: clave });
  if (r.estado !== 202) throw new Error(`registro ${r.estado}`);
  await n.pedir("POST", "/auth/verificar-correo", { token: tokenDe(e.correo.ultimoPara(correo)!.texto) });
  const l = await n.pedir("POST", "/auth/login", { correo, contrasena: clave });
  if (l.estado !== 200) throw new Error(`login ${l.estado}`);
  return n;
}
