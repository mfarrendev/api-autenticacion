// Especificación escrita a mano. La prueba test/openapi.test.ts la compara
// con la tabla de rutas del servidor y llama a cada operación contra el
// servidor real: una ruta sin documentar, o un código de respuesta que la
// especificación no declara, hacen caer la suite.

const err = (descripcion: string) => ({
  description: descripcion,
  content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
});
const json = (schema: object) => ({ required: true, content: { "application/json": { schema } } });
const comunes = {
  "400": err("Entrada inválida"),
  "403": err("Origen no permitido (CSRF) o sin permiso"),
  "415": err("El cuerpo debe ser application/json"),
};
const conSesion = { security: [{ sesion: [] }] };
const credenciales = {
  type: "object",
  additionalProperties: false,
  required: ["correo", "contrasena"],
  properties: { correo: { type: "string", format: "email", maxLength: 254 }, contrasena: { type: "string", minLength: 1 } },
};
const token = { type: "string", pattern: "^[A-Za-z0-9_-]{43}$" };
const usuario = {
  type: "object",
  properties: { id: { type: "integer" }, correo: { type: "string" }, rol: { enum: ["usuario", "admin"] } },
};
const nota = {
  type: "object",
  properties: { id: { type: "integer" }, titulo: { type: "string" }, cuerpo: { type: "string" }, creada: { type: "integer" } },
};
const idParam = [{ name: "id", in: "path", required: true, schema: { type: "integer", minimum: 1 } }];

export const especificacion = {
  openapi: "3.1.0",
  info: { title: "API de autenticación de referencia", version: "0.1.0", license: { name: "MIT", identifier: "MIT" } },
  components: {
    securitySchemes: { sesion: { type: "apiKey", in: "cookie", name: "__Host-sid" } },
    schemas: {
      Error: { type: "object", required: ["error"], properties: { error: { type: "string" } } },
    },
  },
  paths: {
    "/auth/registro": {
      post: {
        summary: "Registro. Responde igual exista o no el correo.",
        requestBody: json(credenciales),
        responses: { "202": { description: "Aceptado" }, ...comunes },
      },
    },
    "/auth/verificar-correo": {
      post: {
        summary: "Confirma el correo con el token recibido.",
        requestBody: json({ type: "object", required: ["token"], properties: { token } }),
        responses: { "200": { description: "Verificado" }, ...comunes },
      },
    },
    "/auth/login": {
      post: {
        summary: "Inicia sesión y entrega una cookie de sesión nueva.",
        requestBody: json(credenciales),
        responses: {
          "200": { description: "Sesión iniciada", content: { "application/json": { schema: usuario } } },
          "401": err("Credenciales inválidas (mismo mensaje exista o no la cuenta)"),
          "429": err("Bloqueo temporal por intentos fallidos; trae Retry-After"),
          ...comunes,
        },
      },
    },
    "/auth/logout": {
      post: { summary: "Cierra la sesión actual.", ...conSesion, responses: { "204": { description: "Cerrada" }, "401": err("Sin sesión"), "403": comunes["403"] } },
    },
    "/auth/logout-todas": {
      post: { summary: "Cierra todas las sesiones del usuario.", ...conSesion, responses: { "204": { description: "Cerradas" }, "401": err("Sin sesión"), "403": comunes["403"] } },
    },
    "/auth/recuperar": {
      post: {
        summary: "Pide un enlace de recuperación. Responde igual exista o no el correo.",
        requestBody: json({ type: "object", required: ["correo"], properties: { correo: { type: "string", format: "email" } } }),
        responses: { "202": { description: "Aceptado" }, ...comunes },
      },
    },
    "/auth/restablecer": {
      post: {
        summary: "Cambia la clave con un token de un solo uso y cierra todas las sesiones.",
        requestBody: json({ type: "object", required: ["token", "contrasena"], properties: { token, contrasena: { type: "string" } } }),
        responses: { "200": { description: "Clave cambiada" }, ...comunes },
      },
    },
    "/yo": {
      get: { summary: "Usuario de la sesión.", ...conSesion, responses: { "200": { description: "Usuario", content: { "application/json": { schema: usuario } } }, "401": err("Sin sesión") } },
    },
    "/notas": {
      get: { summary: "Notas propias.", ...conSesion, responses: { "200": { description: "Lista", content: { "application/json": { schema: { type: "array", items: nota } } } }, "401": err("Sin sesión") } },
      post: {
        summary: "Crea una nota del usuario de la sesión.",
        ...conSesion,
        requestBody: json({ type: "object", required: ["titulo", "cuerpo"], additionalProperties: false, properties: { titulo: { type: "string", maxLength: 200 }, cuerpo: { type: "string" } } }),
        responses: { "201": { description: "Creada", content: { "application/json": { schema: nota } } }, "401": err("Sin sesión"), ...comunes },
      },
    },
    "/notas/{id}": {
      get: { summary: "Una nota propia. La ajena responde 404.", ...conSesion, parameters: idParam, responses: { "200": { description: "Nota" }, "401": err("Sin sesión"), "404": err("No existe o no es tuya") } },
      delete: { summary: "Borra una nota propia.", ...conSesion, parameters: idParam, responses: { "204": { description: "Borrada" }, "401": err("Sin sesión"), "403": comunes["403"], "404": err("No existe o no es tuya") } },
    },
    "/admin/usuarios": {
      get: { summary: "Lista de usuarios (solo admin).", ...conSesion, responses: { "200": { description: "Lista" }, "401": err("Sin sesión"), "403": err("No es admin") } },
    },
    "/admin/auditoria": {
      get: { summary: "Últimos eventos de seguridad (solo admin).", ...conSesion, responses: { "200": { description: "Eventos" }, "401": err("Sin sesión"), "403": err("No es admin") } },
    },
    "/openapi.json": {
      get: { summary: "Esta especificación.", responses: { "200": { description: "Documento OpenAPI 3.1" } } },
    },
  },
} as const;
