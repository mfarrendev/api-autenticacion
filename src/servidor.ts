import { createServer, type Server } from "node:http";
import { mkdirSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { dirname } from "node:path";
import { crearApp, configPorOmision, type Config } from "./app.ts";
import { hashear, revisarPolitica } from "./contrasenas.ts";
import { CorreoArchivo, CorreoConsola } from "./correo.ts";
import { abrirBase } from "./db.ts";

export async function levantar(cfg: Config, puerto = 0, host = "127.0.0.1"): Promise<{ servidor: Server; url: string }> {
  const app = crearApp(cfg);
  const servidor = createServer((req, res) => void app.manejar(req, res));
  servidor.headersTimeout = 10_000;
  servidor.requestTimeout = 15_000;
  await new Promise<void>((ok) => servidor.listen(puerto, host, ok));
  const { port } = servidor.address() as AddressInfo;
  return { servidor, url: `http://${host}:${port}` };
}

async function principal(): Promise<void> {
  const ruta = process.env.BASE ?? "datos/api.db";
  if (ruta !== ":memory:") mkdirSync(dirname(ruta), { recursive: true });
  const db = abrirBase(ruta);
  const correo = process.env.CORREO_ARCHIVO ? new CorreoArchivo(process.env.CORREO_ARCHIVO) : new CorreoConsola();
  const cfg = configPorOmision({
    db,
    correo,
    origenes: (process.env.ORIGENES ?? "http://localhost:3000").split(","),
    urlPublica: process.env.URL_PUBLICA ?? "http://localhost:3000",
    confiarProxy: process.env.CONFIAR_PROXY === "1",
  });
  // Primer admin opcional, desde el entorno. La clave pasa por la misma política.
  const { ADMIN_CORREO: ac, ADMIN_CONTRASENA: ak } = process.env;
  if (ac && ak) {
    const problema = revisarPolitica(ak, ac);
    if (problema) throw new Error(`ADMIN_CONTRASENA rechazada: ${problema}`);
    db.prepare("INSERT INTO usuarios (correo, hash, rol, verificado, creado) VALUES (?, ?, 'admin', 1, ?) ON CONFLICT(correo) DO NOTHING").run(
      ac.trim().toLowerCase(),
      await hashear(ak, cfg.versionHash),
      Date.now(),
    );
  }
  const { url } = await levantar(cfg, Number(process.env.PUERTO ?? 8080), process.env.HOST ?? "127.0.0.1");
  console.log(`API escuchando en ${url}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await principal();
}
