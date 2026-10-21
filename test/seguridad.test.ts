// Pruebas de punta a punta contra el servidor real en un puerto efímero.
// Cada bloque cubre una propiedad del modelo de amenazas del README.
//
// Medición (2026-10-20): se puso cada defecto a mano, se corrió este archivo
// con el reportero JSON exigiendo que corrieran las 36 pruebas, y se revirtió.
//   1. login sin hash señuelo para el correo inexistente: cae 1 de 36
//      (el tiempo de respuesta).
//   2. login sin cerrar la sesión que traía el navegador: cae 1 de 36
//      (fijación de sesión).
//   3. verNota sin comparar el dueño: cae 1 de 36 (BOLA).
//   4. consumirToken sin "AND usado = 0": caen 2 de 36 (token reutilizado y
//      usos simultáneos).
//   5. origenPermitido devuelve true cuando hay Origin (y, por cómo quedó la
//      mutación, también sin él): caen 4 de 36 (los tres de CSRF y el de
//      auditoría, que esperaba el evento csrf-rechazado).
//   6. bloqueo por cuenta solo si la cuenta existe: caen 2 de 36 (bloqueo de
//      una cuenta inexistente y bloqueo creciente).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hashear } from "../src/contrasenas.ts";
import { hashSecreto } from "../src/secretos.ts";
import { CLAVE, entorno, Navegador, ORIGEN, tokenDe, usuarioListo, type Entorno } from "./ayuda.ts";

let e: Entorno;
beforeEach(async () => {
  e = await entorno();
});
afterEach(async () => {
  await e.cerrar();
});

const MIN = 60_000;

async function mediana(f: () => Promise<unknown>, n = 7): Promise<number> {
  const ts: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await f();
    ts.push(performance.now() - t0);
  }
  return ts.sort((a, b) => a - b)[Math.floor(n / 2)]!;
}

describe("enumeración de usuarios", () => {
  it("login: misma respuesta para correo inexistente y para clave equivocada", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    const existe = await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: "no es la clave correcta" });
    const noExiste = await n.pedir("POST", "/auth/login", { correo: "nadie@ejemplo.cl", contrasena: "no es la clave correcta" });
    expect(existe.estado).toBe(401);
    expect(noExiste.estado).toBe(existe.estado);
    expect(noExiste.cuerpo).toEqual(existe.cuerpo);
  });

  it("login: el tiempo de respuesta no delata si la cuenta existe", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    // Correos distintos en cada intento para no tocar el bloqueo por cuenta.
    let i = 0;
    const tExiste = await mediana(() => n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: `equivocada numero ${i++}` }));
    const tNoExiste = await mediana(() => n.pedir("POST", "/auth/login", { correo: `nadie${i++}@ejemplo.cl`, contrasena: "equivocada numero x" }));
    const razon = tNoExiste / tExiste;
    expect(razon).toBeGreaterThan(0.5);
    expect(razon).toBeLessThan(2);
  });

  it("registro y recuperación responden igual exista o no el correo", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    const r1 = await n.pedir("POST", "/auth/registro", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    const r2 = await n.pedir("POST", "/auth/registro", { correo: "beto@ejemplo.cl", contrasena: CLAVE });
    expect([r1.estado, r1.cuerpo]).toEqual([r2.estado, r2.cuerpo]);
    // La dueña de la cuenta sí se entera del intento de registro.
    expect(e.correo.ultimoPara("ana@ejemplo.cl")?.asunto).toMatch(/registro/i);
    const p1 = await n.pedir("POST", "/auth/recuperar", { correo: "ana@ejemplo.cl" });
    const p2 = await n.pedir("POST", "/auth/recuperar", { correo: "nadie@ejemplo.cl" });
    expect([p1.estado, p1.cuerpo]).toEqual([p2.estado, p2.cuerpo]);
  });
});

describe("fuerza bruta", () => {
  it("tras cinco fallos la cuenta se bloquea, incluso para la clave correcta, y se libera al vencer", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    for (let i = 0; i < 5; i++) {
      expect((await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: `intento fallido ${i}` })).estado).toBe(401);
    }
    const bloqueado = await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    expect(bloqueado.estado).toBe(429);
    expect(Number(bloqueado.cabeceras.get("retry-after"))).toBe(30);
    e.reloj.avanzar(31_000);
    expect((await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE })).estado).toBe(200);
  });

  it("el bloqueo crece: cada fallo después del umbral duplica la espera", async () => {
    const n = new Navegador(e.url);
    const intentar = () => n.pedir("POST", "/auth/login", { correo: "nadie@ejemplo.cl", contrasena: "intento fallido" });
    for (let i = 0; i < 5; i++) await intentar();
    const esperas: number[] = [];
    for (let k = 0; k < 3; k++) {
      const r = await intentar();
      esperas.push(Number(r.cabeceras.get("retry-after")));
      e.reloj.avanzar(esperas[k]! * 1000);
      await intentar(); // falla otra vez y alarga el bloqueo
    }
    expect(esperas).toEqual([30, 60, 120]);
  });

  it("una cuenta inexistente se bloquea igual que una real: el bloqueo no sirve para enumerar", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    const ultimo: number[] = [];
    for (const correo of ["ana@ejemplo.cl", "nadie@ejemplo.cl"]) {
      let r;
      for (let i = 0; i < 6; i++) r = await n.pedir("POST", "/auth/login", { correo, contrasena: "intento fallido" });
      ultimo.push(r!.estado);
    }
    expect(ultimo).toEqual([429, 429]);
  });

  it("por IP: muchas cuentas distintas desde la misma dirección terminan bloqueadas", async () => {
    await e.cerrar();
    e = await entorno({ bloqueoIp: { umbral: 8, baseMs: 60_000, techoMs: 60 * MIN, olvidoMs: 60 * MIN } });
    await usuarioListo(e, "ana@ejemplo.cl");
    const n = new Navegador(e.url);
    for (let i = 0; i < 8; i++) await n.pedir("POST", "/auth/login", { correo: `rociado${i}@ejemplo.cl`, contrasena: "verano2026verano" });
    expect((await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE })).estado).toBe(429);
  });
});

describe("sesiones", () => {
  it("la cookie sale HttpOnly, Secure, SameSite=Lax, con prefijo __Host- y sin Domain", async () => {
    const n = new Navegador(e.url);
    await n.pedir("POST", "/auth/registro", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    await n.pedir("POST", "/auth/verificar-correo", { token: tokenDe(e.correo.ultimoPara("ana@ejemplo.cl")!.texto) });
    const r = await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    const c = r.setCookie[0]!;
    expect(c).toMatch(/^__Host-sid=[A-Za-z0-9_-]{43};/);
    for (const atributo of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) expect(c).toContain(atributo);
    expect(c).not.toMatch(/Domain=/i);
  });

  it("fijación de sesión: un identificador plantado antes del login no queda autenticado", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const atacante = await usuarioListo(e, "mallory@ejemplo.cl");
    const plantado = atacante.cookie!;
    const victima = new Navegador(e.url);
    victima.cookie = plantado;
    const r = await victima.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    expect(r.estado).toBe(200);
    expect(victima.cookie).not.toBe(plantado);
    // Con el identificador plantado el atacante no ve a la víctima: ni siquiera a sí mismo.
    expect((await atacante.pedir("GET", "/yo")).estado).toBe(401);
    expect((await victima.pedir("GET", "/yo")).cuerpo.correo).toBe("ana@ejemplo.cl");
  });

  it("la base guarda el hash del identificador, no el identificador", async () => {
    const n = await usuarioListo(e, "ana@ejemplo.cl");
    const id = n.cookie!.split("=")[1]!;
    const filas = e.cfg.db.prepare("SELECT id_hash FROM sesiones").all() as { id_hash: string }[];
    expect(filas.map((f) => f.id_hash)).toEqual([hashSecreto(id)]);
    expect(JSON.stringify(filas)).not.toContain(id);
  });

  it("cerrar sesión invalida el identificador en el servidor, no solo la cookie", async () => {
    const n = await usuarioListo(e, "ana@ejemplo.cl");
    const viejo = n.cookie!;
    expect((await n.pedir("POST", "/auth/logout")).estado).toBe(204);
    const copia = new Navegador(e.url);
    copia.cookie = viejo;
    expect((await copia.pedir("GET", "/yo")).estado).toBe(401);
  });

  it("cerrar todas las sesiones cierra también las de otros dispositivos", async () => {
    const pc = await usuarioListo(e, "ana@ejemplo.cl");
    const celular = new Navegador(e.url);
    await celular.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    expect((await celular.pedir("GET", "/yo")).estado).toBe(200);
    expect((await pc.pedir("POST", "/auth/logout-todas")).estado).toBe(204);
    expect((await celular.pedir("GET", "/yo")).estado).toBe(401);
  });

  it("expira por inactividad", async () => {
    const n = await usuarioListo(e, "ana@ejemplo.cl");
    e.reloj.avanzar(29 * MIN);
    expect((await n.pedir("GET", "/yo")).estado).toBe(200);
    e.reloj.avanzar(30 * MIN);
    expect((await n.pedir("GET", "/yo")).estado).toBe(401);
  });

  it("expira por plazo absoluto aunque se use sin pausa", async () => {
    const n = await usuarioListo(e, "ana@ejemplo.cl");
    for (let h = 0; h < 12 * 4 - 1; h++) {
      e.reloj.avanzar(15 * MIN);
      expect((await n.pedir("GET", "/yo")).estado).toBe(200);
    }
    e.reloj.avanzar(15 * MIN);
    expect((await n.pedir("GET", "/yo")).estado).toBe(401);
  });
});

describe("recuperación de clave", () => {
  async function pedirToken(correo: string): Promise<string> {
    await new Navegador(e.url).pedir("POST", "/auth/recuperar", { correo });
    return tokenDe(e.correo.ultimoPara(correo)!.texto);
  }

  it("el token sirve una sola vez", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    const n = new Navegador(e.url);
    expect((await n.pedir("POST", "/auth/restablecer", { token: t, contrasena: "otra frase nueva y larga" })).estado).toBe(200);
    const reuso = await n.pedir("POST", "/auth/restablecer", { token: t, contrasena: "la del atacante, larga" });
    expect([reuso.estado, reuso.cuerpo.error]).toEqual([400, "token-invalido"]);
    expect((await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: "otra frase nueva y larga" })).estado).toBe(200);
  });

  it("dos usos simultáneos del mismo token: gana uno solo", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    const n = new Navegador(e.url);
    const rs = await Promise.all([1, 2, 3].map((k) => n.pedir("POST", "/auth/restablecer", { token: t, contrasena: `frase simultanea ${k}x` })));
    expect(rs.map((r) => r.estado).sort()).toEqual([200, 400, 400]);
  });

  it("vence a los 15 minutos", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    e.reloj.avanzar(15 * MIN);
    expect((await new Navegador(e.url).pedir("POST", "/auth/restablecer", { token: t, contrasena: "otra frase nueva y larga" })).estado).toBe(400);
  });

  it("pedir uno nuevo anula el anterior", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const viejo = await pedirToken("ana@ejemplo.cl");
    await pedirToken("ana@ejemplo.cl");
    expect((await new Navegador(e.url).pedir("POST", "/auth/restablecer", { token: viejo, contrasena: "otra frase nueva y larga" })).estado).toBe(400);
  });

  it("restablecer cierra todas las sesiones abiertas y la clave vieja deja de servir", async () => {
    const sesion = await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    await new Navegador(e.url).pedir("POST", "/auth/restablecer", { token: t, contrasena: "otra frase nueva y larga" });
    expect((await sesion.pedir("GET", "/yo")).estado).toBe(401);
    expect((await new Navegador(e.url).pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE })).estado).toBe(401);
  });

  it("una clave nueva que no cumple la política no quema el token", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    const n = new Navegador(e.url);
    expect((await n.pedir("POST", "/auth/restablecer", { token: t, contrasena: "corta" })).cuerpo.motivo).toBe("muy-corta");
    expect((await n.pedir("POST", "/auth/restablecer", { token: t, contrasena: "otra frase nueva y larga" })).estado).toBe(200);
  });

  it("la base guarda el hash del token, no el token", async () => {
    await usuarioListo(e, "ana@ejemplo.cl");
    const t = await pedirToken("ana@ejemplo.cl");
    const guardados = JSON.stringify(e.cfg.db.prepare("SELECT * FROM tokens").all());
    expect(guardados).not.toContain(t);
    expect(guardados).toContain(hashSecreto(t));
  });
});

describe("verificación de correo", () => {
  it("sin verificar no hay sesión; el aviso solo aparece con la clave correcta", async () => {
    const n = new Navegador(e.url);
    await n.pedir("POST", "/auth/registro", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    const mala = await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: "no es la clave correcta" });
    expect(mala.cuerpo.error).toBe("credenciales-invalidas");
    const buena = await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
    expect([buena.estado, buena.cuerpo.error]).toEqual([403, "correo-no-verificado"]);
    expect(buena.setCookie).toEqual([]);
    await n.pedir("POST", "/auth/verificar-correo", { token: tokenDe(e.correo.ultimoPara("ana@ejemplo.cl")!.texto) });
    expect((await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: CLAVE })).estado).toBe(200);
  });
});

describe("autorización", () => {
  it("BOLA: un usuario no lee ni borra la nota de otro, y la respuesta no confirma que exista", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    const beto = await usuarioListo(e, "beto@ejemplo.cl");
    const { cuerpo: nota } = await ana.pedir("POST", "/notas", { titulo: "privada", cuerpo: "solo para Ana" });
    const lee = await beto.pedir("GET", `/notas/${nota.id}`);
    const inexistente = await beto.pedir("GET", "/notas/999999");
    expect([lee.estado, lee.cuerpo]).toEqual([inexistente.estado, inexistente.cuerpo]);
    expect(lee.estado).toBe(404);
    expect((await beto.pedir("DELETE", `/notas/${nota.id}`)).estado).toBe(404);
    expect((await beto.pedir("GET", "/notas")).cuerpo).toEqual([]);
    expect((await ana.pedir("GET", `/notas/${nota.id}`)).cuerpo.cuerpo).toBe("solo para Ana");
  });

  it("asignación masiva: no se puede crear una nota a nombre de otro", async () => {
    const beto = await usuarioListo(e, "beto@ejemplo.cl");
    const r = await beto.pedir("POST", "/notas", { titulo: "x", cuerpo: "y", usuario_id: 1 });
    expect([r.estado, r.cuerpo.error]).toEqual([400, "entrada-invalida"]);
  });

  it("las rutas de admin rechazan a un usuario común y aceptan al admin", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    expect((await ana.pedir("GET", "/admin/usuarios")).estado).toBe(403);
    e.cfg.db.prepare("UPDATE usuarios SET rol = 'admin' WHERE correo = ?").run("ana@ejemplo.cl");
    const r = await ana.pedir("GET", "/admin/usuarios");
    expect(r.estado).toBe(200);
    expect(JSON.stringify(r.cuerpo)).not.toContain("scrypt$");
  });

  it("el admin sí puede leer una nota ajena", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    const admin = await usuarioListo(e, "admin@ejemplo.cl");
    e.cfg.db.prepare("UPDATE usuarios SET rol = 'admin' WHERE correo = ?").run("admin@ejemplo.cl");
    const { cuerpo: nota } = await ana.pedir("POST", "/notas", { titulo: "t", cuerpo: "c" });
    expect((await admin.pedir("GET", `/notas/${nota.id}`)).estado).toBe(200);
  });
});

describe("CSRF", () => {
  it("rechaza un método que cambia estado desde otro origen, aun con cookie válida", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    const r = await ana.pedir("POST", "/notas", { titulo: "inyectada", cuerpo: "x" }, { Origin: "https://malo.test" });
    expect([r.estado, r.cuerpo.error]).toEqual([403, "origen-no-permitido"]);
    expect((await ana.pedir("GET", "/notas")).cuerpo).toEqual([]);
    expect((await ana.pedir("POST", "/auth/logout-todas", undefined, { Origin: "null" })).estado).toBe(403);
  });

  it("sin Origin exige Sec-Fetch-Site: same-origin", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    expect((await ana.pedir("POST", "/notas", { titulo: "a", cuerpo: "b" }, { Origin: "" })).estado).toBe(403);
    expect((await ana.pedir("POST", "/notas", { titulo: "a", cuerpo: "b" }, { Origin: "", "Sec-Fetch-Site": "cross-site" })).estado).toBe(403);
    expect((await ana.pedir("POST", "/notas", { titulo: "a", cuerpo: "b" }, { Origin: "", "Sec-Fetch-Site": "same-origin" })).estado).toBe(201);
  });

  it("también protege el login (CSRF de login)", async () => {
    await usuarioListo(e, "mallory@ejemplo.cl");
    const r = await new Navegador(e.url).pedir("POST", "/auth/login", { correo: "mallory@ejemplo.cl", contrasena: CLAVE }, { Origin: "https://malo.test" });
    expect(r.estado).toBe(403);
    expect(r.setCookie).toEqual([]);
  });

  it("un formulario simple (text/plain) no pasa", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    const r = await ana.pedir("POST", "/notas", '{"titulo":"a","cuerpo":"b"}', { "Content-Type": "text/plain" });
    expect(r.estado).toBe(415);
  });
});

describe("entrada y cabeceras", () => {
  it("cada respuesta lleva las cabeceras de seguridad, también los errores", async () => {
    const n = new Navegador(e.url);
    for (const r of [await n.pedir("GET", "/openapi.json"), await n.pedir("GET", "/no-existe"), await n.pedir("GET", "/yo")]) {
      expect(r.cabeceras.get("content-security-policy")).toContain("default-src 'none'");
      expect(r.cabeceras.get("x-content-type-options")).toBe("nosniff");
      expect(r.cabeceras.get("strict-transport-security")).toContain("max-age=");
      expect(r.cabeceras.get("cache-control")).toBe("no-store");
      expect(r.cabeceras.get("x-powered-by")).toBeNull();
    }
  });

  it("valida con esquema: campos extra, correo mal formado, cuerpo enorme y JSON roto", async () => {
    const n = new Navegador(e.url);
    expect((await n.pedir("POST", "/auth/login", { correo: "no-es-correo", contrasena: "x" })).cuerpo.campos).toEqual(["correo"]);
    expect((await n.pedir("POST", "/auth/registro", { correo: "a@b.cl", contrasena: CLAVE, rol: "admin" })).estado).toBe(400);
    expect((await n.pedir("POST", "/auth/login", { correo: "a@b.cl", contrasena: "x".repeat(20_000) })).estado).toBe(413);
    expect((await n.pedir("POST", "/auth/login", "{roto")).estado).toBe(400);
    expect((await n.pedir("GET", "/notas/abc")).estado).toBe(404);
  });

  it("el registro aplica la política y no dice nada del correo", async () => {
    const r = await new Navegador(e.url).pedir("POST", "/auth/registro", { correo: "ana@ejemplo.cl", contrasena: "password1234" });
    expect([r.estado, r.cuerpo.motivo]).toEqual([400, "comun"]);
  });
});

describe("re-hash al subir parámetros", () => {
  it("un hash v1 se reemplaza por uno v2 al iniciar sesión", async () => {
    e.cfg.db
      .prepare("INSERT INTO usuarios (correo, hash, verificado, creado) VALUES (?, ?, 1, 0)")
      .run("vieja@ejemplo.cl", await hashear(CLAVE, 1));
    const r = await new Navegador(e.url).pedir("POST", "/auth/login", { correo: "vieja@ejemplo.cl", contrasena: CLAVE });
    expect(r.estado).toBe(200);
    const { hash } = e.cfg.db.prepare("SELECT hash FROM usuarios WHERE correo = ?").get("vieja@ejemplo.cl") as { hash: string };
    expect(hash).toMatch(/^scrypt\$2\$/);
    expect((await new Navegador(e.url).pedir("POST", "/auth/login", { correo: "vieja@ejemplo.cl", contrasena: CLAVE })).estado).toBe(200);
  });
});

describe("auditoría", () => {
  it("registra los eventos de seguridad sin contraseñas, tokens ni identificadores de sesión", async () => {
    const ana = await usuarioListo(e, "ana@ejemplo.cl");
    const secretos: string[] = [CLAVE, ana.cookie!.split("=")[1]!, tokenDe(e.correo.enviados[0]!.texto)];
    const n = new Navegador(e.url);
    await n.pedir("POST", "/auth/login", { correo: "ana@ejemplo.cl", contrasena: "clave tecleada mal 1" });
    await n.pedir("POST", "/auth/login", { correo: "clave tecleada en el correo@x.cl", contrasena: CLAVE });
    await n.pedir("POST", "/auth/recuperar", { correo: "ana@ejemplo.cl" });
    const t = tokenDe(e.correo.ultimoPara("ana@ejemplo.cl")!.texto);
    secretos.push(t, "otra frase nueva y larga", "clave tecleada mal 1");
    await n.pedir("POST", "/auth/restablecer", { token: t, contrasena: "otra frase nueva y larga" });
    await ana.pedir("POST", "/notas", { titulo: "x", cuerpo: "y" }, { Origin: "https://malo.test" });

    const filas = e.cfg.db.prepare("SELECT * FROM auditoria").all() as { evento: string }[];
    const eventos = filas.map((f) => f.evento);
    for (const ev of ["registro", "correo-verificado", "login-ok", "login-fallido", "recuperacion-pedida", "recuperacion-usada", "csrf-rechazado"]) {
      expect(eventos).toContain(ev);
    }
    const todo = JSON.stringify(filas);
    for (const s of secretos) expect(todo).not.toContain(s);
    expect(todo).not.toContain("ana@ejemplo.cl");
  });
});

it("la URL del correo apunta al origen configurado", async () => {
  await new Navegador(e.url).pedir("POST", "/auth/registro", { correo: "ana@ejemplo.cl", contrasena: CLAVE });
  expect(e.correo.ultimoPara("ana@ejemplo.cl")!.texto).toContain(`${ORIGEN}/verificar#`);
});
