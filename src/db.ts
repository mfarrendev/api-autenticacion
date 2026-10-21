import { DatabaseSync } from "node:sqlite";

export type Rol = "usuario" | "admin";

export interface Usuario {
  id: number;
  correo: string;
  hash: string;
  rol: Rol;
  verificado: number;
  creado: number;
}

export interface Sesion {
  id_hash: string;
  usuario_id: number;
  creada: number;
  ultima_actividad: number;
}

export interface Nota {
  id: number;
  usuario_id: number;
  titulo: string;
  cuerpo: string;
  creada: number;
}

const ESQUEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY,
  correo TEXT NOT NULL UNIQUE,
  hash TEXT NOT NULL,
  rol TEXT NOT NULL DEFAULT 'usuario' CHECK (rol IN ('usuario','admin')),
  verificado INTEGER NOT NULL DEFAULT 0,
  creado INTEGER NOT NULL
);
-- Se guarda el SHA-256 del identificador de sesión, nunca el identificador:
-- quien lea la base no puede usar lo que lee para entrar.
CREATE TABLE IF NOT EXISTS sesiones (
  id_hash TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  creada INTEGER NOT NULL,
  ultima_actividad INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sesiones_usuario ON sesiones(usuario_id);
CREATE TABLE IF NOT EXISTS tokens (
  hash TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL CHECK (tipo IN ('recuperar','verificar')),
  vence INTEGER NOT NULL,
  usado INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS intentos (
  clave TEXT PRIMARY KEY,
  fallos INTEGER NOT NULL,
  ultimo INTEGER NOT NULL,
  bloqueado_hasta INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notas (
  id INTEGER PRIMARY KEY,
  usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  titulo TEXT NOT NULL,
  cuerpo TEXT NOT NULL,
  creada INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auditoria (
  id INTEGER PRIMARY KEY,
  fecha INTEGER NOT NULL,
  evento TEXT NOT NULL,
  usuario_id INTEGER,
  ip TEXT,
  detalle TEXT
);
`;

export function abrirBase(ruta = ":memory:"): DatabaseSync {
  const db = new DatabaseSync(ruta);
  db.exec(ESQUEMA);
  return db;
}
