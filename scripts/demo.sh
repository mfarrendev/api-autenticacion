#!/bin/bash
# Levanta el servidor compilado en el puerto 8097 con una base temporal y
# recorre el flujo con curl. Requiere `npm run build` antes.
cd "$(dirname "$0")/.."
W=$(mktemp -d)
BASE=$W/api.db PUERTO=8097 CORREO_ARCHIVO=$W/correos.jsonl node --no-warnings dist/servidor.js &
PID=$!; sleep 1
U=http://127.0.0.1:8097
p() { echo "\$ POST $1 $2"; curl -s -H 'Origin: http://localhost:3000' -H 'Content-Type: application/json' -d "$2" -w '  -> %{http_code}\n' $U$1; }
p /auth/registro '{"correo":"ana@ejemplo.cl","contrasena":"password1234"}'
p /auth/registro '{"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}'
p /auth/registro '{"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}'
T=$(head -1 $W/correos.jsonl | grep -o '#[A-Za-z0-9_-]*' | tr -d '#')
p /auth/verificar-correo "{\"token\":\"$T\"}"
p /auth/login '{"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}'
p /auth/login '{"correo":"nadie@ejemplo.cl","contrasena":"no es la clave correcta"}'
for i in 1 2 3 4 5; do p /auth/login '{"correo":"ana@ejemplo.cl","contrasena":"no es la clave correcta"}'; done
p /auth/login '{"correo":"ana@ejemplo.cl","contrasena":"caballo bateria grapa correcta"}'
echo '$ POST /auth/recuperar desde https://malo.test'
curl -s -H 'Origin: https://malo.test' -H 'Content-Type: application/json' -d '{"correo":"ana@ejemplo.cl"}' -w '  -> %{http_code}\n' $U/auth/recuperar
kill $PID; wait $PID 2>/dev/null; rm -rf "$W"
