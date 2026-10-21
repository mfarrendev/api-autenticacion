// La especificación OpenAPI se valida contra las rutas reales: cada ruta del
// servidor está documentada, cada operación documentada existe, y cada
// operación llamada de verdad responde un código que la especificación declara.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { crearApp } from "../src/app.ts";
import { especificacion } from "../src/openapi.ts";
import { entorno, Navegador, usuarioListo, type Entorno } from "./ayuda.ts";

type Operacion = { responses: Record<string, unknown>; security?: unknown; parameters?: unknown };
const paths = especificacion.paths as unknown as Record<string, Record<string, Operacion>>;

const documentadas = Object.entries(paths).flatMap(([ruta, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${ruta}`));

let e: Entorno;
beforeAll(async () => {
  e = await entorno();
});
afterAll(async () => {
  await e.cerrar();
});

describe("especificación OpenAPI 3.1", () => {
  it("es 3.1 y cada operación declara respuestas", () => {
    expect(especificacion.openapi).toMatch(/^3\.1\./);
    for (const ops of Object.values(paths)) for (const op of Object.values(ops)) expect(Object.keys(op.responses).length).toBeGreaterThan(0);
  });

  it("documenta exactamente las rutas que el servidor atiende", () => {
    const { rutas } = crearApp(e.cfg);
    const reales = rutas.map((r) => `${r.metodo} ${r.patron.replace(/:(\w+)/g, "{$1}")}`);
    expect([...reales].sort()).toEqual([...documentadas].sort());
  });

  it("las rutas con sesión declaran el esquema de seguridad y las públicas no", () => {
    const { rutas } = crearApp(e.cfg);
    for (const r of rutas) {
      const op = paths[r.patron.replace(/:(\w+)/g, "{$1}")]![r.metodo.toLowerCase()]!;
      expect(Boolean(op.security), `${r.metodo} ${r.patron}`).toBe(r.acceso !== "publico");
    }
  });

  it("el servidor sirve la misma especificación", async () => {
    const r = await new Navegador(e.url).pedir("GET", "/openapi.json");
    expect(r.cuerpo).toEqual(JSON.parse(JSON.stringify(especificacion)));
  });

  it("cada operación responde, sin sesión y con sesión, un código declarado", async () => {
    const anonimo = new Navegador(e.url);
    const conSesion = await usuarioListo(e, "contrato@ejemplo.cl");
    const { cuerpo: nota } = await conSesion.pedir("POST", "/notas", { titulo: "t", cuerpo: "c" });
    const fallas: string[] = [];
    for (const op of documentadas) {
      const [metodo, plantilla] = op.split(" ") as [string, string];
      const ruta = plantilla.replace("{id}", String(nota.id));
      const cuerpo = metodo === "POST" ? {} : undefined;
      for (const [quien, n] of [["anonimo", anonimo], ["con-sesion", conSesion]] as const) {
        // logout y logout-todas al final: cerrarían la sesión del resto.
        if (quien === "con-sesion" && plantilla.startsWith("/auth/logout")) continue;
        const r = await n.pedir(metodo, ruta, cuerpo);
        const declarados = Object.keys(paths[plantilla]![metodo.toLowerCase()]!.responses);
        if (!declarados.includes(String(r.estado))) fallas.push(`${op} (${quien}) -> ${r.estado}, declara ${declarados.join(",")}`);
      }
    }
    for (const plantilla of ["/auth/logout", "/auth/logout-todas"]) {
      const r = await conSesion.pedir("POST", plantilla);
      if (!(String(r.estado) in paths[plantilla]!.post!.responses)) fallas.push(`POST ${plantilla} -> ${r.estado}`);
      await conSesion.pedir("POST", "/auth/login", { correo: "contrato@ejemplo.cl", contrasena: "caballo bateria grapa correcta" });
    }
    expect(fallas).toEqual([]);
  });
});
