// Lista corta de contraseñas comunes y filtradas. NIST 800-63B pide rechazar
// las que aparecen en listas de contraseñas conocidas; en producción esta
// lista se reemplaza por una grande (por ejemplo, el corpus de Have I Been
// Pwned consultado por k-anonimato). Va en minúsculas: se compara así.
export const CONTRASENAS_COMUNES: ReadonlySet<string> = new Set([
  "123456789012", "1234567890123", "123456789", "12345678", "1234567890",
  "password", "password1", "password123", "password1234", "passw0rd",
  "qwertyuiop", "qwerty123456", "qwertyuiop123", "1q2w3e4r5t6y", "1qaz2wsx3edc",
  "iloveyou", "iloveyou123", "princess", "sunshine", "football", "baseball",
  "superman", "starwars", "trustno1", "welcome", "welcome123", "welcome1234",
  "letmein", "letmein123", "monkey", "dragon", "master", "shadow", "michael",
  "abc123", "abcdefghijkl", "abcdef123456", "aaaaaaaaaaaa", "000000000000",
  "111111111111", "contrasena", "contraseña", "contrasena123", "contraseña123",
  "micontrasena", "micontraseña", "teamo123456", "holahola1234", "chile1234567",
  "administrador", "administrator", "admin123456", "adminadmin", "changeme",
  "changeme123", "correcthorsebatterystaple", "passwordpassword", "qazwsxedcrfv",
  "zaq12wsxcde3", "asdfghjkl123", "asdfghjklñ", "mypassword123", "secret123456",
]);
