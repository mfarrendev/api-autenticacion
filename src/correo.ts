import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface Mensaje {
  para: string;
  asunto: string;
  texto: string;
}

/**
 * El envío de correo es una interfaz. Este repositorio no habla con ningún
 * proveedor: trae una implementación que escribe a consola, otra que agrega
 * a un archivo JSONL y otra en memoria para las pruebas.
 */
export interface Correo {
  enviar(m: Mensaje): Promise<void>;
}

export class CorreoConsola implements Correo {
  async enviar(m: Mensaje): Promise<void> {
    process.stdout.write(`[correo] para=${m.para} asunto=${m.asunto}\n${m.texto}\n`);
  }
}

export class CorreoArchivo implements Correo {
  constructor(private readonly ruta: string) {}
  async enviar(m: Mensaje): Promise<void> {
    await mkdir(dirname(this.ruta), { recursive: true });
    await appendFile(this.ruta, JSON.stringify({ ...m, fecha: new Date().toISOString() }) + "\n", { mode: 0o600 });
  }
}

export class CorreoMemoria implements Correo {
  readonly enviados: Mensaje[] = [];
  async enviar(m: Mensaje): Promise<void> {
    this.enviados.push(m);
  }
  ultimoPara(para: string): Mensaje | undefined {
    return this.enviados.filter((m) => m.para === para).at(-1);
  }
}
