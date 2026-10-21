import type { IncomingMessage, ServerResponse } from "node:http";
import type { DatabaseSync } from "node:sqlite";
import type { z } from "zod";
import { auditar, huellaCorreo } from "./auditoria.ts";
import { bloqueadoHasta, limpiar, registrarFallo, type ReglasBloqueo } from "./bloqueo.ts";
import { hashear, revisarPolitica, verificar, verificarSenuelo, type VersionHash } from "./contrasenas.ts";
import type { Correo } from "./correo.ts";
import type { Nota, Rol, Usuario } from "./db.ts";
import * as E from "./esquemas.ts";
import {
  borrarCookieSesion,
  COOKIE_SESION,
  cookieSesion,
  ErrorHttp,
  leerCookies,
  leerJson,
  origenPermitido,
  responder,
} from "./http.ts";
import { especificacion } from "./openapi.ts";
import { cerrarSesion, cerrarTodas, crearSesion, leerSesion, type PlazosSesion } from "./sesiones.ts";
import { consumirToken, emitirToken } from "./tokens.ts";

export interface Config {
  db: DatabaseSync;
  correo: Correo;
  /** Orígenes desde los que se aceptan métodos que cambian estado. */
  origenes: string[];
  /** URL pública de la interfaz, para armar los enlaces de los correos. */
  urlPublica: string;
  versionHash: VersionHash;
  sesion: PlazosSesion;
  bloqueoCuenta: ReglasBloqueo;
  bloqueoIp: ReglasBloqueo;
  vigenciaRecuperarMs: number;
  vigenciaVerificarMs: number;
  /** Solo detrás de un proxy propio: toma la IP de X-Forwarded-For. */
  confiarProxy: boolean;
  ahora: () => number;
}

const MIN = 60_000;
export function configPorOmision(parcial: Partial<Config> & Pick<Config, "db" | "correo">): Config {
  return {
    origenes: ["http://localhost:3000"],
    urlPublica: "http://localhost:3000",
    versionHash: 2,
    sesion: { absolutoMs: 12 * 60 * MIN, inactividadMs: 30 * MIN },
    bloqueoCuenta: { umbral: 5, baseMs: 30_000, techoMs: 15 * MIN, olvidoMs: 60 * MIN },
    bloqueoIp: { umbral: 50, baseMs: 60_000, techoMs: 60 * MIN, olvidoMs: 60 * MIN },
    vigenciaRecuperarMs: 15 * MIN,
    vigenciaVerificarMs: 24 * 60 * MIN,
    confiarProxy: false,
    ahora: Date.now,
    ...parcial,
  };
}

type Acceso = "publico" | "usuario" | "admin";

interface Contexto {
  req: IncomingMessage;
  res: ServerResponse;
  params: Record<string, string>;
  ip: string;
  usuario: Usuario | null;
  sesionId: string | null;
}

export interface Ruta {
  metodo: "GET" | "POST" | "DELETE";
  patron: string;
  acceso: Acceso;
  manejar: (c: Contexto) => Promise<void> | void;
}

export function crearApp(cfg: Config) {
  const { db } = cfg;
  const origenes = new Set(cfg.origenes);

  const porCorreo = db.prepare("SELECT * FROM usuarios WHERE correo = ?");
  const porId = db.prepare("SELECT * FROM usuarios WHERE id = ?");

  async function cuerpo<T extends z.ZodTypeAny>(c: Contexto, esquema: T): Promise<z.infer<T>> {
    const r = esquema.safeParse(await leerJson(c.req));
    if (!r.success) {
      throw new ErrorHttp(400, "entrada-invalida", {
        campos: r.error.issues.map((i) => i.path.join(".") || "(cuerpo)"),
      });
    }
    return r.data;
  }

  const ctx = (c: Contexto, detalle?: Record<string, string | number>) => ({ usuarioId: c.usuario?.id ?? null, ip: c.ip, detalle });

  function nuevaSesion(c: Contexto, usuarioId: number): void {
    // Rotación: cualquier sesión que trajera el navegador muere aquí, y la
    // nueva sale con un identificador que nadie conocía antes del login.
    if (c.sesionId) cerrarSesion(db, c.sesionId);
    const id = crearSesion(db, usuarioId, cfg.ahora());
    c.res.setHeader("Set-Cookie", cookieSesion(id, Math.floor(cfg.sesion.absolutoMs / 1000)));
  }

  function verNota(c: Contexto): Nota {
    const nota = db.prepare("SELECT * FROM notas WHERE id = ?").get(Number(c.params.id)) as Nota | undefined;
    // Autorización por recurso: la nota ajena responde igual que la que no
    // existe (404), para no confirmar qué identificadores hay.
    if (!nota || (nota.usuario_id !== c.usuario!.id && c.usuario!.rol !== "admin")) {
      if (nota) auditar(db, cfg.ahora(), "acceso-denegado", ctx(c, { recurso: `nota:${nota.id}` }));
      throw new ErrorHttp(404, "no-encontrado");
    }
    return nota;
  }

  const rutas: Ruta[] = [
    {
      metodo: "POST",
      patron: "/auth/registro",
      acceso: "publico",
      async manejar(c) {
        const b = await cuerpo(c, E.Registro);
        const problema = revisarPolitica(b.contrasena, b.correo);
        if (problema) throw new ErrorHttp(400, "contrasena-rechazada", { motivo: problema });
        // Se hashea siempre, antes de saber si el correo existe: así las dos
        // ramas tardan lo mismo.
        const hash = await hashear(b.contrasena, cfg.versionHash);
        const existente = porCorreo.get(b.correo) as Usuario | undefined;
        if (existente) {
          await cfg.correo.enviar({
            para: b.correo,
            asunto: "Intento de registro con tu correo",
            texto: "Alguien intentó crear una cuenta con este correo, que ya tiene una. Si fuiste tú, inicia sesión o recupera tu clave.",
          });
          auditar(db, cfg.ahora(), "registro-repetido", { ip: c.ip, usuarioId: existente.id });
        } else {
          const r = db.prepare("INSERT INTO usuarios (correo, hash, creado) VALUES (?, ?, ?)").run(b.correo, hash, cfg.ahora());
          const id = Number(r.lastInsertRowid);
          const t = emitirToken(db, id, "verificar", cfg.ahora(), cfg.vigenciaVerificarMs);
          await cfg.correo.enviar({
            para: b.correo,
            asunto: "Confirma tu correo",
            texto: `Abre este enlace para confirmar tu correo: ${cfg.urlPublica}/verificar#${t}`,
          });
          auditar(db, cfg.ahora(), "registro", { ip: c.ip, usuarioId: id });
        }
        // Misma respuesta exista o no la cuenta: el registro no sirve para enumerar.
        responder(c.res, 202, { mensaje: "Si el correo es válido, te enviamos instrucciones." });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/verificar-correo",
      acceso: "publico",
      async manejar(c) {
        const b = await cuerpo(c, E.VerificarCorreo);
        const id = consumirToken(db, b.token, "verificar", cfg.ahora());
        if (id === null) {
          auditar(db, cfg.ahora(), "token-invalido", ctx(c, { motivo: "verificar" }));
          throw new ErrorHttp(400, "token-invalido");
        }
        db.prepare("UPDATE usuarios SET verificado = 1 WHERE id = ?").run(id);
        auditar(db, cfg.ahora(), "correo-verificado", { ip: c.ip, usuarioId: id });
        responder(c.res, 200, { mensaje: "Correo verificado." });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/login",
      acceso: "publico",
      async manejar(c) {
        const b = await cuerpo(c, E.Login);
        const ahora = cfg.ahora();
        const claveCuenta = `cuenta:${b.correo}`;
        const claveIp = `ip:${c.ip}`;
        const hasta = Math.max(bloqueadoHasta(db, claveCuenta, ahora), bloqueadoHasta(db, claveIp, ahora));
        if (hasta) {
          auditar(db, ahora, "login-bloqueado", ctx(c, { correo_huella: huellaCorreo(b.correo) }));
          throw new ErrorHttp(429, "demasiados-intentos", { reintentarEn: Math.ceil((hasta - ahora) / 1000) });
        }
        const u = porCorreo.get(b.correo) as Usuario | undefined;
        let r = { valida: false, rehashear: false };
        if (u) r = await verificar(b.contrasena, u.hash, cfg.versionHash);
        else await verificarSenuelo(b.contrasena, cfg.versionHash);
        if (!u || !r.valida) {
          registrarFallo(db, claveCuenta, ahora, cfg.bloqueoCuenta);
          registrarFallo(db, claveIp, ahora, cfg.bloqueoIp);
          auditar(db, ahora, "login-fallido", { ip: c.ip, usuarioId: u?.id ?? null, detalle: { correo_huella: huellaCorreo(b.correo) } });
          throw new ErrorHttp(401, "credenciales-invalidas");
        }
        limpiar(db, claveCuenta);
        if (r.rehashear) {
          db.prepare("UPDATE usuarios SET hash = ? WHERE id = ?").run(await hashear(b.contrasena, cfg.versionHash), u.id);
          auditar(db, ahora, "rehash", { ip: c.ip, usuarioId: u.id, detalle: { version: cfg.versionHash } });
        }
        // Solo se revela que falta verificar a quien ya probó la clave.
        if (!u.verificado) {
          auditar(db, ahora, "login-sin-verificar", { ip: c.ip, usuarioId: u.id });
          throw new ErrorHttp(403, "correo-no-verificado");
        }
        nuevaSesion(c, u.id);
        auditar(db, ahora, "login-ok", { ip: c.ip, usuarioId: u.id });
        responder(c.res, 200, { id: u.id, correo: u.correo, rol: u.rol });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/logout",
      acceso: "usuario",
      manejar(c) {
        cerrarSesion(db, c.sesionId!);
        auditar(db, cfg.ahora(), "logout", ctx(c));
        responder(c.res, 204, undefined, { "Set-Cookie": borrarCookieSesion() });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/logout-todas",
      acceso: "usuario",
      manejar(c) {
        const n = cerrarTodas(db, c.usuario!.id);
        auditar(db, cfg.ahora(), "logout-todas", ctx(c, { sesiones_cerradas: n }));
        responder(c.res, 204, undefined, { "Set-Cookie": borrarCookieSesion() });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/recuperar",
      acceso: "publico",
      async manejar(c) {
        const b = await cuerpo(c, E.Recuperar);
        const u = porCorreo.get(b.correo) as Usuario | undefined;
        if (u) {
          const t = emitirToken(db, u.id, "recuperar", cfg.ahora(), cfg.vigenciaRecuperarMs);
          await cfg.correo.enviar({
            para: u.correo,
            asunto: "Restablece tu clave",
            texto: `Este enlace vale 15 minutos y una sola vez: ${cfg.urlPublica}/restablecer#${t}`,
          });
        }
        auditar(db, cfg.ahora(), "recuperacion-pedida", { ip: c.ip, usuarioId: u?.id ?? null, detalle: { correo_huella: huellaCorreo(b.correo) } });
        responder(c.res, 202, { mensaje: "Si el correo es válido, te enviamos instrucciones." });
      },
    },
    {
      metodo: "POST",
      patron: "/auth/restablecer",
      acceso: "publico",
      async manejar(c) {
        const b = await cuerpo(c, E.Restablecer);
        // Primero la política (sin el correo, que aún no sabemos), para no
        // quemar el token por una clave corta.
        const p1 = revisarPolitica(b.contrasena);
        if (p1) throw new ErrorHttp(400, "contrasena-rechazada", { motivo: p1 });
        const id = consumirToken(db, b.token, "recuperar", cfg.ahora());
        if (id === null) {
          auditar(db, cfg.ahora(), "token-invalido", ctx(c, { motivo: "recuperar" }));
          throw new ErrorHttp(400, "token-invalido");
        }
        const u = porId.get(id) as Usuario | undefined;
        if (!u) throw new ErrorHttp(400, "token-invalido");
        const p2 = revisarPolitica(b.contrasena, u.correo);
        if (p2) throw new ErrorHttp(400, "contrasena-rechazada", { motivo: p2 });
        db.prepare("UPDATE usuarios SET hash = ?, verificado = 1 WHERE id = ?").run(await hashear(b.contrasena, cfg.versionHash), id);
        // La clave cambió: toda sesión abierta con la anterior se cierra.
        const n = cerrarTodas(db, id);
        limpiar(db, `cuenta:${u.correo}`);
        auditar(db, cfg.ahora(), "recuperacion-usada", { ip: c.ip, usuarioId: id, detalle: { sesiones_cerradas: n } });
        responder(c.res, 200, { mensaje: "Clave actualizada. Inicia sesión de nuevo." });
      },
    },
    {
      metodo: "GET",
      patron: "/yo",
      acceso: "usuario",
      manejar(c) {
        const u = c.usuario!;
        responder(c.res, 200, { id: u.id, correo: u.correo, rol: u.rol });
      },
    },
    {
      metodo: "GET",
      patron: "/notas",
      acceso: "usuario",
      manejar(c) {
        const notas = db.prepare("SELECT id, titulo, cuerpo, creada FROM notas WHERE usuario_id = ? ORDER BY id").all(c.usuario!.id);
        responder(c.res, 200, notas);
      },
    },
    {
      metodo: "POST",
      patron: "/notas",
      acceso: "usuario",
      async manejar(c) {
        const b = await cuerpo(c, E.NuevaNota);
        // El dueño sale de la sesión, nunca del cuerpo (asignación masiva).
        const r = db.prepare("INSERT INTO notas (usuario_id, titulo, cuerpo, creada) VALUES (?, ?, ?, ?)").run(c.usuario!.id, b.titulo, b.cuerpo, cfg.ahora());
        responder(c.res, 201, { id: Number(r.lastInsertRowid), titulo: b.titulo, cuerpo: b.cuerpo });
      },
    },
    {
      metodo: "GET",
      patron: "/notas/:id",
      acceso: "usuario",
      manejar(c) {
        const n = verNota(c);
        responder(c.res, 200, { id: n.id, titulo: n.titulo, cuerpo: n.cuerpo, creada: n.creada });
      },
    },
    {
      metodo: "DELETE",
      patron: "/notas/:id",
      acceso: "usuario",
      manejar(c) {
        const n = verNota(c);
        db.prepare("DELETE FROM notas WHERE id = ?").run(n.id);
        responder(c.res, 204, undefined);
      },
    },
    {
      metodo: "GET",
      patron: "/admin/usuarios",
      acceso: "admin",
      manejar(c) {
        responder(c.res, 200, db.prepare("SELECT id, correo, rol, verificado, creado FROM usuarios ORDER BY id").all());
      },
    },
    {
      metodo: "GET",
      patron: "/admin/auditoria",
      acceso: "admin",
      manejar(c) {
        const filas = db.prepare("SELECT id, fecha, evento, usuario_id, ip, detalle FROM auditoria ORDER BY id DESC LIMIT 200").all();
        responder(c.res, 200, filas);
      },
    },
    {
      metodo: "GET",
      patron: "/openapi.json",
      acceso: "publico",
      manejar(c) {
        responder(c.res, 200, especificacion);
      },
    },
  ];

  function calzar(metodo: string, ruta: string): { r: Ruta; params: Record<string, string> } | null {
    const partes = ruta.split("/");
    for (const r of rutas) {
      if (r.metodo !== metodo) continue;
      const p = r.patron.split("/");
      if (p.length !== partes.length) continue;
      const params: Record<string, string> = {};
      const ok = p.every((seg, i) => {
        const real = partes[i]!;
        if (seg.startsWith(":")) {
          if (!/^[1-9][0-9]{0,15}$/.test(real)) return false;
          params[seg.slice(1)] = real;
          return true;
        }
        return seg === real;
      });
      if (ok) return { r, params };
    }
    return null;
  }

  function ipDe(req: IncomingMessage): string {
    if (cfg.confiarProxy) {
      const xff = req.headers["x-forwarded-for"];
      const primera = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
      if (primera) return primera;
    }
    return req.socket.remoteAddress ?? "desconocida";
  }

  async function manejar(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const ip = ipDe(req);
    try {
      const url = new URL(req.url ?? "/", "http://interno");
      const hallada = calzar(req.method ?? "GET", url.pathname);
      if (!hallada) throw new ErrorHttp(404, "no-encontrado");
      if (!origenPermitido(req, origenes)) {
        auditar(db, cfg.ahora(), "csrf-rechazado", { ip, detalle: { ruta: url.pathname } });
        throw new ErrorHttp(403, "origen-no-permitido");
      }
      const sesionId = leerCookies(req).get(COOKIE_SESION) ?? null;
      let usuario: Usuario | null = null;
      if (sesionId && hallada.r.acceso !== "publico") {
        const s = leerSesion(db, sesionId, cfg.ahora(), cfg.sesion);
        if (s) usuario = (porId.get(s.usuario_id) as Usuario | undefined) ?? null;
      }
      if (hallada.r.acceso !== "publico" && !usuario) throw new ErrorHttp(401, "sin-sesion");
      if (hallada.r.acceso === "admin" && usuario!.rol !== ("admin" satisfies Rol)) {
        auditar(db, cfg.ahora(), "acceso-denegado", { ip, usuarioId: usuario!.id, detalle: { ruta: url.pathname } });
        throw new ErrorHttp(403, "prohibido");
      }
      await hallada.r.manejar({ req, res, params: hallada.params, ip, usuario, sesionId });
    } catch (e) {
      if (e instanceof ErrorHttp) {
        const cab: Record<string, string> = {};
        if (e.estado === 429 && typeof e.extra.reintentarEn === "number") cab["Retry-After"] = String(e.extra.reintentarEn);
        responder(res, e.estado, { error: e.codigo, ...e.extra }, cab);
      } else {
        // El detalle del error va al registro del servidor, nunca al cliente.
        console.error(e);
        responder(res, 500, { error: "interno" });
      }
    }
  }

  return { manejar, rutas };
}
