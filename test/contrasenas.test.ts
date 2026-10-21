import { describe, expect, it } from "vitest";
import { hashear, revisarPolitica, verificar } from "../src/contrasenas.ts";

describe("política de contraseñas (NIST 800-63B)", () => {
  it("exige largo mínimo y máximo contando caracteres, no bytes", () => {
    expect(revisarPolitica("corta123")).toBe("muy-corta");
    expect(revisarPolitica("a".repeat(129) + "xyz")).toBe("muy-larga");
    // Once puntos de código pero catorce unidades UTF-16: corta.
    expect(revisarPolitica("ñandú𠀀𠀀𠀀sur")).toBe("muy-corta");
    expect(revisarPolitica("ñandú𠀀𠀀𠀀sury")).toBeNull();
  });

  it("no exige reglas de composición: una frase en minúsculas es válida", () => {
    expect(revisarPolitica("caballo bateria grapa correcta")).toBeNull();
  });

  it("rechaza contraseñas comunes, sin importar mayúsculas", () => {
    expect(revisarPolitica("Password1234")).toBe("comun");
    expect(revisarPolitica("CONTRASEÑA123")).toBe("comun");
  });

  it("rechaza la que contiene la parte local del correo", () => {
    expect(revisarPolitica("soymariajose2026", "mariajose@ejemplo.cl")).toBe("contiene-correo");
  });
});

describe("hash scrypt versionado", () => {
  it("verifica la correcta, rechaza la incorrecta y pide re-hash si la versión es vieja", async () => {
    const h1 = await hashear("una frase bastante larga", 1);
    expect(h1).toMatch(/^scrypt\$1\$/);
    expect(await verificar("una frase bastante larga", h1, 2)).toEqual({ valida: true, rehashear: true });
    expect(await verificar("una frase bastante largA", h1, 2)).toEqual({ valida: false, rehashear: false });
    const h2 = await hashear("una frase bastante larga", 2);
    expect(await verificar("una frase bastante larga", h2, 2)).toEqual({ valida: true, rehashear: false });
  });

  it("usa sal: dos hashes de la misma clave difieren", async () => {
    expect(await hashear("una frase bastante larga", 2)).not.toBe(await hashear("una frase bastante larga", 2));
  });

  it("normaliza NFKC: la misma clave compuesta o descompuesta verifica", async () => {
    const h = await hashear("canción de cuna larga", 2);
    expect((await verificar("canción de cuna larga".normalize("NFD"), h, 2)).valida).toBe(true);
  });

  it("un hash manipulado o de otro formato no verifica", async () => {
    expect((await verificar("x".repeat(12), "bcrypt$2$abc$def", 2)).valida).toBe(false);
    expect((await verificar("x".repeat(12), "scrypt$9$abc$def", 2)).valida).toBe(false);
  });
});
