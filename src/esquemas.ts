import { z } from "zod";

const correo = z.string().trim().toLowerCase().max(254).email();
// El tope de 1024 es solo para no hashear megabytes; la política (12 a 128
// caracteres) se revisa aparte para dar un motivo claro.
const contrasena = z.string().min(1).max(1024);
const token = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const Registro = z.object({ correo, contrasena }).strict();
export const Login = z.object({ correo, contrasena }).strict();
export const Recuperar = z.object({ correo }).strict();
export const Restablecer = z.object({ token, contrasena }).strict();
export const VerificarCorreo = z.object({ token }).strict();
export const NuevaNota = z
  .object({ titulo: z.string().trim().min(1).max(200), cuerpo: z.string().max(10_000) })
  .strict();
