# api-autenticacion

API REST de referencia con autenticación completa: registro, verificación de
correo, inicio y cierre de sesión, recuperación de clave, roles y
autorización por recurso. Está escrita para leerse: cada defensa vive en un
lugar, lleva el motivo en un comentario y tiene una prueba que la ataca
contra el servidor real.

Node 24 y TypeScript, sin framework web (`node:http`), base SQLite con el
módulo `node:sqlite` del propio Node, validación con zod. La única
dependencia de ejecución es zod.

## El problema

Casi todos los fallos de autenticación no vienen de la criptografía sino de
los bordes: un mensaje de error distinto para el correo que no existe, una
sesión que no rota al iniciar sesión, un token de recuperación que se puede
usar dos veces, un `GET /notas/17` que no pregunta de quién es la nota 17.
Este repositorio junta esos bordes en un solo servicio pequeño y los prueba
uno por uno.

## Diseño y decisiones

- **Contraseñas** (`src/contrasenas.ts`). Política NIST 800-63B: entre 12 y
  128 caracteres contados en puntos de código, normalización NFKC, rechazo de
  contraseñas comunes y de las que contienen la parte local del correo, y
  ninguna regla de composición. Hash scrypt con sal de 16 bytes; el hash
  guardado dice su versión (`scrypt$2$sal$hash`), así que subir el costo no
  rompe cuentas: el hash viejo se verifica con sus parámetros y se reemplaza
  al iniciar sesión. Comparación con `timingSafeEqual`.
- **Sesiones** (`src/sesiones.ts`). Identificador opaco de 256 bits en una
  cookie `__Host-sid` con `HttpOnly`, `Secure`, `SameSite=Lax` y sin
  `Domain`. En la base se guarda su SHA-256, no el identificador. Vencen a
  las 12 horas desde el login y a los 30 minutos sin uso. Al iniciar sesión
  se cierra la que trajera el navegador y se emite una nueva.
- **Login sin enumeración.** Misma respuesta (401, `credenciales-invalidas`)
  exista o no el correo; si no existe se verifica igual contra un hash
  señuelo para que el tiempo no lo delate. El registro y la recuperación
  responden siempre 202 con el mismo texto; a la dueña de una cuenta ya
  existente le llega un correo avisando del intento. El aviso de "correo no
  verificado" solo aparece después de acertar la clave.
- **Fuerza bruta** (`src/bloqueo.ts`). Bloqueo progresivo por correo tecleado
  (5 fallos, luego 30 s, 60 s, 120 s... hasta 15 min) y por IP (50 fallos,
  techo de una hora). El contador por correo corre también para correos que
  no existen: si solo se bloquearan las cuentas reales, el bloqueo mismo
  serviría para enumerarlas.
- **Tokens de un solo uso** (`src/tokens.ts`). Recuperación (15 min) y
  verificación (24 h). Se guardan hasheados, el consumo es un solo `UPDATE
  ... WHERE usado = 0 AND vence > ? RETURNING`, de modo que dos peticiones
  simultáneas no ganan las dos, y pedir uno nuevo anula el anterior.
  Restablecer la clave cierra todas las sesiones. Una clave nueva que no
  cumple la política se rechaza antes de consumir el token.
- **Correo** (`src/correo.ts`). Es una interfaz. Vienen tres
  implementaciones: consola, archivo JSONL y memoria (para las pruebas).
  Ninguna habla con un proveedor real.
- **Autorización.** Cada ruta declara si es pública, de usuario o de admin, y
  la comprobación ocurre en un solo lugar del despachador. Las notas se
  autorizan por recurso: la nota ajena responde 404, igual que la que no
  existe. El dueño de una nota nueva sale de la sesión; los esquemas son
  `.strict()`, así que un `usuario_id` en el cuerpo se rechaza.
- **CSRF** (`src/http.ts`). Todo método que no sea GET, HEAD u OPTIONS exige
  un `Origin` de la lista configurada o, si el navegador no lo manda,
  `Sec-Fetch-Site: same-origin`. Sin ninguno de los dos se rechaza. Además
  los cuerpos deben ser `application/json`, que un formulario simple no
  puede enviar. Cubre también el login.
- **Cabeceras.** CSP que niega todo (es una API JSON), HSTS, `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP, CORP y
  `Cache-Control: no-store`, en todas las respuestas, errores incluidos.
- **Auditoría** (`src/auditoria.ts`). Tabla `auditoria` con login correcto y
  fallido, bloqueos, registro, verificación, recuperación, CSRF rechazado y
  accesos denegados. El detalle pasa por una lista blanca de campos; en los
  fallos se guarda una huella de 16 hexadecimales del correo tecleado, no el
  correo, porque a veces la gente escribe la clave en ese campo.
- **OpenAPI 3.1** (`src/openapi.ts`), escrita a mano y servida en
  `/openapi.json`. La prueba `test/openapi.test.ts` la compara con la tabla
  de rutas y llama cada operación contra el servidor, con y sin sesión,
  exigiendo que el código devuelto esté declarado.

## Uso

```bash
npm install
npm test           # 49 pruebas, servidor real en puerto efímero
npm run typecheck
npm run build
npm start          # dist/servidor.js en 127.0.0.1:8080
npm run demo       # compila, levanta en 8097 con base temporal y recorre el flujo con curl
```

Variables de entorno de `npm start`:

| Variable | Por omisión | Uso |
| --- | --- | --- |
| `PUERTO`, `HOST` | `8080`, `127.0.0.1` | Dónde escuchar |
| `BASE` | `datos/api.db` | Archivo SQLite (`:memory:` para no guardar) |
| `ORIGENES` | `http://localhost:3000` | Orígenes aceptados para CSRF, separados por coma |
| `URL_PUBLICA` | `http://localhost:3000` | Base de los enlaces en los correos |
| `CORREO_ARCHIVO` | (consola) | Si se define, los correos se agregan a ese JSONL |
| `CONFIAR_PROXY` | `0` | `1` toma la IP de `X-Forwarded-For`; solo detrás de un proxy propio |
| `ADMIN_CORREO`, `ADMIN_CONTRASENA` | | Crea el primer admin al arrancar |

La cookie lleva `Secure`: un navegador no la guarda sobre `http://` salvo en
`localhost`. En producción el servicio va detrás de TLS.

## Salida real

`npm run demo`, tal cual:

```
API escuchando en http://127.0.0.1:8097
$ POST /auth/registro {"correo":"ana@ejemplo.cl","contrasena":"password1234"}
{"error":"contrasena-rechazada","motivo":"comun"}  -> 400
$ POST /auth/registro {"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}
{"mensaje":"Si el correo es válido, te enviamos instrucciones."}  -> 202
$ POST /auth/registro {"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}
{"mensaje":"Si el correo es válido, te enviamos instrucciones."}  -> 202
$ POST /auth/verificar-correo {"token":"B9RojbjKQpuIHcAxJFgHRnjuQCe_-7WsafUct1e8mZ0"}
{"mensaje":"Correo verificado."}  -> 200
$ POST /auth/login {"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}
{"id":1,"correo":"ana@ejemplo.cl","rol":"usuario"}  -> 200
$ POST /auth/login {"correo":"nadie@ejemplo.cl","contrasena":"no es la clave correcta"}
{"error":"credenciales-invalidas"}  -> 401
$ POST /auth/login {"correo":"ana@ejemplo.cl","contrasena":"no es la clave correcta"}
{"error":"credenciales-invalidas"}  -> 401
  (cuatro veces más igual)
$ POST /auth/login {"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}
{"error":"demasiados-intentos","reintentarEn":30}  -> 429
$ POST /auth/recuperar desde https://malo.test
{"error":"origen-no-permitido"}  -> 403
```

El segundo registro con el mismo correo responde igual que el primero. La
clave correcta, después de cinco fallos, recibe 429: el bloqueo no depende
de acertar.

`npm test`:

```
 Test Files  3 passed (3)
      Tests  49 passed (49)
   Duration  9.26s
```

## Modelo de amenazas

Las pruebas están en `test/seguridad.test.ts` salvo que se indique otra cosa.

| Amenaza | Defensa | Prueba |
| --- | --- | --- |
| Enumerar cuentas por el mensaje de login | Misma respuesta 401 para correo inexistente y clave equivocada | "login: misma respuesta para correo inexistente y para clave equivocada" |
| Enumerar cuentas por el tiempo de login | Hash señuelo cuando el correo no existe | "login: el tiempo de respuesta no delata si la cuenta existe" (mediana de 7, razón entre 0,5 y 2) |
| Enumerar por registro o recuperación | 202 con el mismo texto siempre; aviso por correo a la dueña | "registro y recuperación responden igual exista o no el correo" |
| Enumerar por el bloqueo | El contador corre para cualquier correo tecleado | "una cuenta inexistente se bloquea igual que una real" |
| Fuerza bruta sobre una cuenta | Bloqueo progresivo por correo, también para la clave correcta | "tras cinco fallos la cuenta se bloquea..." y "el bloqueo crece..." |
| Rociado de claves desde una IP | Bloqueo por IP | "por IP: muchas cuentas distintas desde la misma dirección..." |
| Robo de la base de datos | scrypt con sal para claves; SHA-256 para sesiones y tokens | "la base guarda el hash del identificador...", "la base guarda el hash del token..." |
| Fijación de sesión | Rotación al iniciar sesión; prefijo `__Host-` | "fijación de sesión: un identificador plantado antes del login no queda autenticado" |
| Robo de cookie por XSS o red | `HttpOnly`, `Secure`, `SameSite=Lax`, HSTS | "la cookie sale HttpOnly, Secure, SameSite=Lax..." |
| Sesión robada que dura para siempre | Expiración absoluta (12 h) y por inactividad (30 min); cierre en el servidor; cerrar todas | "expira por inactividad", "expira por plazo absoluto...", "cerrar sesión invalida...", "cerrar todas las sesiones..." |
| Token de recuperación reutilizado | Consumo atómico de un solo uso | "el token sirve una sola vez", "dos usos simultáneos del mismo token: gana uno solo" |
| Token de recuperación viejo o filtrado | Vence a los 15 min; uno nuevo anula el anterior; restablecer cierra todas las sesiones | "vence a los 15 minutos", "pedir uno nuevo anula el anterior", "restablecer cierra todas las sesiones..." |
| Cuenta con correo ajeno | Verificación de correo antes de la primera sesión | "sin verificar no hay sesión..." |
| BOLA (leer o borrar recursos ajenos) | Autorización por recurso, 404 indistinguible | "BOLA: un usuario no lee ni borra la nota de otro..." |
| Asignación masiva | Esquemas `.strict()`, dueño desde la sesión | "asignación masiva: no se puede crear una nota a nombre de otro" |
| Escalada a funciones de admin | Rol revisado en el despachador | "las rutas de admin rechazan a un usuario común..." |
| CSRF | Verificación de `Origin` / `Sec-Fetch-Site`; solo `application/json` | Bloque "CSRF" (cuatro pruebas, login incluido) |
| Claves débiles | Política NIST 800-63B | `test/contrasenas.test.ts`; "el registro aplica la política..." |
| Hash con parámetros viejos | Versión en el hash y re-hash al iniciar sesión | "un hash v1 se reemplaza por uno v2..."; `test/contrasenas.test.ts` |
| Secretos en la bitácora | Lista blanca de campos; huella del correo en vez del correo | "registra los eventos de seguridad sin contraseñas, tokens ni identificadores de sesión" |
| Entrada maliciosa o gigante | zod, límite de 16 KB, JSON obligatorio | "valida con esquema..." |
| Clickjacking, sniffing, caché de respuestas privadas | Cabeceras de seguridad en toda respuesta | "cada respuesta lleva las cabeceras de seguridad..." |
| Documentación que miente | OpenAPI contrastada con rutas y respuestas reales | `test/openapi.test.ts` |

### Las pruebas que se midieron

Una prueba que nunca falló no demuestra nada. Se introdujeron a mano siete
defectos, se corrió la suite con el reportero JSON comprobando que se
ejecutaran todas las pruebas del archivo, y se revirtió cada uno. Los
resultados están anotados al inicio de `test/seguridad.test.ts` y
`test/openapi.test.ts`:

| Defecto introducido | Cayeron |
| --- | --- |
| Login sin hash señuelo | 1 de 36 (tiempo de respuesta) |
| Login sin cerrar la sesión previa | 1 de 36 (fijación) |
| `verNota` sin comparar dueño | 1 de 36 (BOLA) |
| Token sin `AND usado = 0` | 2 de 36 |
| CSRF que acepta cualquier `Origin` | 4 de 36 |
| Bloqueo solo para cuentas existentes | 2 de 36 |
| Ruta borrada de la especificación | 2 de 5 |

## Limitaciones

- La lista de contraseñas comunes tiene unas sesenta entradas. En producción
  se reemplaza por una lista grande o por una consulta de k-anonimato a un
  servicio de contraseñas filtradas.
- La prueba de tiempo compara medianas con un margen amplio (0,5 a 2). Sirve
  para atrapar la regresión gruesa (sin señuelo la diferencia es de dos
  órdenes de magnitud), no para demostrar ausencia de canal lateral fino.
- El bloqueo vive en la misma base SQLite: con varias instancias detrás de un
  balanceador cada una necesita la misma base, o el contador hay que moverlo
  a un almacén compartido. Un atacante con muchas IP y pocos intentos por
  correo no lo alcanza a ver; eso pide señales adicionales (captcha, MFA).
- El bloqueo por correo permite a un tercero dejar a alguien fuera durante
  el bloqueo vigente. Está acotado por el techo de 15 minutos, pero existe.
- No hay segundo factor, ni cambio de clave con sesión iniciada, ni cambio
  de correo. Son extensiones naturales del mismo patrón de tokens.
- `node:sqlite` sigue marcado como experimental en Node 24 y emite un aviso
  al arrancar.
- La IP se toma del socket; detrás de un proxy hay que activar
  `CONFIAR_PROXY`, y solo si el proxy reescribe `X-Forwarded-For`.

## Licencia

MIT.
