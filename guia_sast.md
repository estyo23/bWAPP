% Guía y Práctica de SAST con Semgrep — Análisis de Código de bWAPP
% Universidad Mariano Gálvez · Diplomado en Ciberseguridad · Curso: Seguridad de Aplicaciones
% 31 de octubre de 2026

# 1. Objetivo y alcance

Esta guía enseña a realizar **SAST (Static Application Security Testing)** con **Semgrep** sobre el código fuente de **bWAPP** (*buggy Web Application*), una aplicación PHP **deliberadamente vulnerable** creada para entrenamiento. El estudiante aprende a instalar Semgrep, escribir y ejecutar reglas, escanear tres proyectos del repositorio, **interpretar los hallazgos con gráficas** y emitir una **postura de seguridad**.

**Objetivos de aprendizaje.** Al finalizar, el estudiante será capaz de:

1. Instalar Semgrep y obtener el código de las 3 aplicaciones (carpetas) de bWAPP.
2. Escribir y leer reglas de Semgrep (modo *taint* y de patrón) mapeadas a OWASP Top 10 y CWE.
3. **Realizar la evaluación SAST** de los 3 proyectos y obtener los hallazgos reales.
4. **Desplegar y presentar los resultados de su evaluación:** generar las gráficas, producir un **reporte/dashboard navegable** (HTML o exportación SARIF) y **exponer** la postura de seguridad ante el grupo.
5. Triar falsos positivos y proponer remediaciones por cada clase de vulnerabilidad.

**Resultados medidos en este laboratorio** (datos reales de la ejecución, repositorio `raesene/bWAPP`): **138 hallazgos** sobre 198 archivos PHP, distribuidos en 3 proyectos.

| Proyecto (carpeta del repo) | Archivos PHP | Hallazgos | Rol |
| --- | --- | --- | --- |
| **Core bWAPP** (`app/`, sin `admin` ni `soap`) | 183 | **103** | Aplicación vulnerable principal |
| **admin** (`app/admin/`) | 3 | **3** | Panel de administración |
| **soap (NuSOAP)** (`app/soap/`) | 12 | **32** | Librería de servicios web (componente de terceros) |

> **Advertencia ético-legal.** El SAST se ejecuta sobre código del que se tiene autorización o que es de entrenamiento. bWAPP es de código abierto y diseñado para ser auditado, por lo que su análisis es lícito. Analizar código de terceros sin permiso puede ser ilegal.

# 2. ¿Qué es SAST y por qué Semgrep?

**SAST** analiza el **código fuente** (sin ejecutarlo) buscando patrones inseguros: entradas del usuario que llegan a consultas SQL, comandos del sistema, salida HTML, etc. Se complementa con DAST (pruebas dinámicas) e IAST.

**Semgrep** es un motor SAST de código abierto que busca patrones con una sintaxis parecida al propio código (no regex frágiles). Sus ventajas para este curso:

- Reglas legibles en **YAML**; se pueden escribir a medida.
- **Modo *taint*** (seguimiento de datos): sigue una entrada del usuario (*source*) hasta un punto peligroso (*sink*), reduciendo falsos positivos.
- Multi-lenguaje, rápido y **ejecutable sin conexión** con reglas locales.
- Exporta a **JSON** y **SARIF** (integrable en CI/CD y GitHub Code Scanning).

# 3. Instalación y preparación del entorno

**3.1 Instalar Semgrep**

```bash
# --- Kali Linux / Debian / Ubuntu ---
pipx install semgrep            # recomendado (PEP 668)
# ó:  pip install semgrep --break-system-packages
semgrep --version               # p.ej. 1.183.0

# --- Windows ---  (requiere Python 3.9+)
pip install semgrep
# ó usar Docker (multiplataforma, sin instalar nada):
docker run --rm -v "%cd%:/src" semgrep/semgrep semgrep --version
```

**3.2 Obtener el código de bWAPP**

```bash
git clone --depth 1 https://github.com/raesene/bWAPP.git
# El código PHP queda en bWAPP/app/
ls bWAPP/app | head
```

> **Se necesita estar autenticado en Git.** El clonado requiere Git instalado y, según el entorno, **haber iniciado sesión en Git/GitHub**. En entornos restringidos o tras un proxy, el clon anónimo puede fallar con el error `fatal: could not read Username for 'https://github.com': terminal prompts disabled`. En ese caso, autentíquese antes de clonar con una de estas opciones:
>
> ```bash
> gh auth login                 # asistente de GitHub CLI (recomendado)
> # ó configurar un token de acceso personal (PAT):
> git config --global credential.helper store
> git clone https://github.com/raesene/bWAPP.git   # pedirá usuario + token
> ```
>
> Alternativa sin Git: descargar el `.zip` del repositorio desde la interfaz web de GitHub (botón *Code → Download ZIP*) y descomprimirlo. El paquete de artefactos de este laboratorio (ver sección 14) ya incluye el código de bWAPP listo para escanear.

**3.3 Modo sin conexión (importante).** El catálogo remoto de reglas (`p/php`, `p/security-audit`, `--config auto`) requiere `semgrep.dev`. Si el entorno no tiene acceso a Internet, se usan **reglas locales** (sección 4), lo cual además es una excelente práctica didáctica.

# 4. Cómo funciona Semgrep: reglas, *taint*, OWASP

Una regla Semgrep define **qué buscar**, **severidad** y **metadatos** (OWASP, CWE). Ejemplo de regla *taint* para inyección SQL usada en este laboratorio:

```yaml
rules:
  - id: php-sql-injection
    languages: [php]
    severity: ERROR
    mode: taint
    message: "Posible inyección SQL (CWE-89): entrada del usuario llega a una consulta."
    metadata: { owasp: "A03:2021 - Injection", cwe: "CWE-89" }
    pattern-sources:              # de dónde viene el dato peligroso
      - pattern: $_GET
      - pattern: $_POST
      - pattern: $_REQUEST
    pattern-sinks:                # dónde se vuelve peligroso
      - pattern: mysql_query(...)
      - pattern: mysqli_query(...)
      - pattern: $O->query(...)
```

El ruleset completo usado cubre **14 reglas** mapeadas a OWASP Top 10 (2021): SQLi, inyección de comandos, `eval`, XSS reflejado, LFI/RFI, LDAP, inyección en correo, redirección abierta, hash/cripto débil, deserialización, `extract()`, credenciales embebidas, `phpinfo()`. El archivo `php-sast-rules.yml` se incluye en el anexo B.

# 5. Ejecución del escaneo (las 3 carpetas)

```bash
R=php-sast-rules.yml
OFF="--metrics=off --disable-version-check --no-git-ignore"

# Proyecto 1 — Core bWAPP (excluye admin y soap)
semgrep scan --config $R $OFF --exclude admin --exclude soap \
  --json -o out/core.json  bWAPP/app

# Proyecto 2 — admin
semgrep scan --config $R $OFF --json -o out/admin.json bWAPP/app/admin

# Proyecto 3 — soap (NuSOAP)
semgrep scan --config $R $OFF --json -o out/soap.json  bWAPP/app/soap
```

**Otros formatos de salida útiles:**

```bash
semgrep scan --config $R --sarif  -o out/core.sarif bWAPP/app   # para GitHub/CI
semgrep scan --config $R --json   -o out/core.json  bWAPP/app   # para gráficas
semgrep scan --config $R --text   bWAPP/app                     # lectura en consola
```

El JSON es la base para las gráficas de la sección 6 (se procesa con un script de Python que agrega por severidad, OWASP y archivo).

# 6. Resultados y gráficas (datos reales del laboratorio)

**6.1 Hallazgos por proyecto y severidad.** El núcleo concentra la gran mayoría de los problemas; `soap` aporta hallazgos de criptografía/terceros; `admin` es el más limpio.

![Hallazgos por proyecto y severidad](charts/01_proyecto_severidad.png)

**6.2 Distribución por severidad (total).** De 138 hallazgos: **66 Alta, 68 Media, 4 Baja**. Casi la mitad son de severidad Alta (inyecciones y RCE).

![Distribución por severidad](charts/04_severidad_donut.png)

**6.3 Por categoría OWASP Top 10 (2021).** Domina **A03: Injection** (73), seguida de **A02: Cryptographic Failures** (29) y **A01: Broken Access Control** (19).

![Hallazgos por categoría OWASP](charts/02_owasp.png)

**6.4 Por tipo de vulnerabilidad.** La **inyección SQL (50)** es el hallazgo más frecuente, seguida de **hash débil (24)** y **redirección abierta (19)**.

![Hallazgos por tipo de vulnerabilidad](charts/03_tipo.png)

**6.5 Archivos más afectados (Core).** Priorización: los archivos con más hallazgos son candidatos a revisión y corrección inmediata.

![Top 10 archivos con más hallazgos](charts/05_top_archivos.png)

# 7. Hallazgos destacados: código vulnerable y remediación

**7.1 Inyección SQL — `sqli_1.php` (A03 / CWE-89, Alta).** La entrada va directa a la consulta; la función `sqli()` no sanea en nivel bajo.

```php
$title = $_GET["title"];
$sql = "SELECT * FROM movies WHERE title LIKE '%" . sqli($title) . "%'";
$recordset = mysql_query($sql, $link);
```

*Remediación:* consultas preparadas — `$stmt = $mysqli->prepare("... WHERE title LIKE ?"); $stmt->bind_param("s", $like);`

**7.2 Inyección de comandos — `commandi.php` (A03 / CWE-78, Alta).**

```php
$target = $_POST["target"];
echo "<p>" . shell_exec("nslookup  " . commandi($target)) . "</p>";
```

*Remediación:* evitar `shell_exec` con datos externos; validar contra lista blanca y usar `escapeshellarg($target)`.

**7.3 Ejecución de código — `php_eval.php` (A03 / CWE-95, Alta).** RCE directo.

```php
@eval($_REQUEST["eval"]);
```

*Remediación:* eliminar `eval`; no existe uso seguro con entrada del usuario.

**7.4 XSS reflejado — `xss_get.php` (A03 / CWE-79, Media).**

```php
$firstname = $_GET["firstname"];
echo "Welcome " . xss($firstname) . " " . xss($lastname);
```

*Remediación:* codificar siempre la salida con `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`.

**7.5 Nota de triaje (falsos positivos).** La regla de criptografía marca `base64_encode()` como "cifrado débil". **Base64 no es cifrado**, pero se incluye a propósito para enseñar que *todo hallazgo SAST se debe triar*: el analista confirma, descarta falsos positivos y ajusta las reglas. Varios de los 5 hallazgos de "Weak Crypto" son de este tipo y deben revisarse.

# 8. Postura de seguridad

Se calcula un **índice ponderado** = (Alta×5) + (Media×3) + (Baja×1) = **538 puntos de riesgo** sobre 198 archivos. Semáforo por proyecto:

| Proyecto | Hallazgos | Alta | Postura | Justificación |
| --- | --- | --- | --- | --- |
| **Core bWAPP** | 103 | mayoría | 🔴 **Crítica** | SQLi masiva, RCE (`eval`, comandos), XSS, LFI |
| **soap (NuSOAP)** | 32 | parcial | 🟠 **Alta** | Cripto débil y riesgo de componente de terceros; requiere triaje |
| **admin** | 3 | baja | 🟡 **Media** | Pocos hallazgos, pero incluye divulgación (`phpinfo`) |

**Lectura ejecutiva.** La aplicación está **en estado crítico**, como corresponde a un entorno de entrenamiento: predomina **A03 Injection (53 %)**, con múltiples caminos a ejecución remota de código. En una aplicación real, estos hallazgos **bloquearían el despliegue**. Prioridades: (1) parametrizar todas las consultas SQL, (2) eliminar `eval`/`shell_exec` con entrada externa, (3) codificar toda salida HTML, (4) sustituir MD5/SHA1 por `password_hash()`.

# 9. Práctica guiada (entregable del estudiante)

El estudiante reproduce el flujo y entrega un informe. Tareas:

1. **T1 — Entorno:** instalar Semgrep y clonar bWAPP; captura de `semgrep --version` y de `ls bWAPP/app`.
2. **T2 — Reglas:** explicar 3 reglas del ruleset (una *taint* y dos de patrón) e indicar su OWASP/CWE.
3. **T3 — Escaneo:** ejecutar las 3 carpetas y adjuntar los conteos por proyecto (JSON).
4. **T4 — Gráficas:** generar al menos **3 gráficas** (por severidad, por OWASP y por archivo) a partir del JSON.
5. **T5 — Hallazgos:** documentar **5 hallazgos** (clase, archivo, línea, fragmento, OWASP/CWE y remediación).
6. **T6 — Triaje:** identificar **1 falso positivo** y justificarlo; proponer un ajuste a la regla.
7. **T7 — Postura:** redactar la postura de seguridad con el semáforo y 4 prioridades de remediación.
8. **T8 — Despliegue de resultados:** **desplegar y presentar** los resultados de la evaluación — un **reporte navegable** (dashboard HTML, PDF, o SARIF cargado en GitHub/`localhost`) que reúna las gráficas, los hallazgos y la postura — y exponerlo ante el grupo.

# 10. Rúbrica de calificación (100 puntos)

Se aprueba con **70**. La evidencia reproducible (comando + salida + gráfica) es obligatoria.

| # | Criterio | Peso | Excelente (100 % del peso) | Suficiente (~60 %) | Insuficiente (0–30 %) |
| --- | --- | --- | --- | --- | --- |
| 1 | Entorno y clonado (T1) | 10 | Semgrep + bWAPP con evidencia; autenticación en Git resuelta | Instala pero sin evidencia completa | No funciona |
| 2 | Comprensión de reglas (T2) | 10 | 3 reglas bien explicadas con OWASP/CWE | Explicación parcial | Sin comprensión |
| 3 | Escaneo de las 3 carpetas (T3) | 15 | 3 escaneos con conteos y JSON | 1–2 carpetas | Sin escaneo |
| 4 | Gráficas (T4) | 10 | ≥ 3 gráficas correctas desde el JSON | 1–2 gráficas | Sin gráficas |
| 5 | Hallazgos documentados (T5) | 20 | 5 con línea, fragmento y remediación | 3–4 incompletos | < 3 |
| 6 | Triaje de falsos positivos (T6) | 10 | Falso positivo justificado + ajuste de regla | Lo menciona sin ajuste | No lo aborda |
| 7 | Postura de seguridad (T7) | 15 | Semáforo + prioridades + lectura ejecutiva | Postura genérica | Ausente |
| 8 | **Despliegue y presentación de resultados (T8)** | 10 | Reporte navegable desplegado (dashboard HTML/SARIF/PDF) + exposición clara | Entrega el reporte pero sin desplegarlo/presentarlo | No despliega ni presenta |

**Total: 100 puntos.** Se aprueba con **70**. Un hallazgo sin evidencia verificable (comando + salida + gráfica) no puntúa.

**Puntos extra (+5):** integrar SARIF en un flujo CI (GitHub Actions) con el dashboard publicado, o escribir una regla *taint* nueva y detectar un hallazgo no cubierto.

# 11. Integración en CI/CD (opcional)

```yaml
# .github/workflows/semgrep.yml
name: semgrep-sast
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install semgrep
      - run: semgrep scan --config php-sast-rules.yml --sarif -o semgrep.sarif .
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: semgrep.sarif }
```

Así cada *pull request* se escanea automáticamente y los hallazgos aparecen en la pestaña *Security* del repositorio.

# 12. Anexo A — Comandos de referencia rápida

```bash
semgrep --version                                   # versión
semgrep scan --config regla.yml ./codigo            # escanear con regla local
semgrep scan --config regla.yml --json -o r.json .  # salida JSON (gráficas)
semgrep scan --config regla.yml --sarif -o r.sarif .# salida SARIF (CI/CD)
semgrep scan --config regla.yml --severity ERROR .  # solo severidad alta
semgrep scan --config regla.yml --exclude vendor .  # excluir carpetas
semgrep scan --config p/php .                        # ruleset remoto (requiere semgrep.dev)
```

# 13. Anexo B — Referencias

- Semgrep (documentación y escritura de reglas): <https://semgrep.dev/docs/>
- OWASP Top 10 (2021): <https://owasp.org/Top10/>
- CWE — Common Weakness Enumeration: <https://cwe.mitre.org/>
- bWAPP (buggy web application), Malik Mesellem: <http://www.itsecgames.com>
- Repositorio usado en el laboratorio: <https://github.com/raesene/bWAPP>
- SARIF (formato de resultados de análisis estático): <https://sarifweb.azurewebsites.net/>

# 14. Anexo C — Paquete de artefactos del laboratorio

Se adjunta el archivo **`bwapp-sast-lab.zip`** con todo lo necesario para reproducir la prueba sin depender del acceso a Internet:

| Ruta dentro del ZIP | Contenido |
| --- | --- |
| `bWAPP-app/` | Código PHP de bWAPP (las 3 carpetas: raíz, `admin/`, `soap/`) listo para escanear |
| `semgrep/php-sast-rules.yml` | Ruleset local de Semgrep (14 reglas, OWASP/CWE) |
| `semgrep/analyze.py` | Script de agregación y generación de gráficas |
| `semgrep/out/*.json` | Salidas JSON de los 3 escaneos |
| `semgrep/summary.json` | Resumen agregado (conteos por severidad, OWASP, archivo) |
| `charts/*.png` | Las 5 gráficas de la sección 6 |
| `README.txt` | Pasos para reproducir el laboratorio |

Reproducción rápida:

```bash
unzip bwapp-sast-lab.zip && cd bwapp-sast-lab
semgrep scan --config semgrep/php-sast-rules.yml --metrics=off \
  --exclude admin --exclude soap --json -o semgrep/out/core.json bWAPP-app
python3 semgrep/analyze.py      # regenera las gráficas
```

# 15. Manual visual — Obtener bWAPP desde GitHub en la web

**Paso 1. Abrir el repositorio.** En el navegador, ir a `https://github.com/raesene/bWAPP`. Se ve el listado de archivos (carpeta `app/`), el botón verde **Code** y las pestañas **Code / Issues / … / Security**.

![Repositorio bWAPP en GitHub](screens/gh1_repo.jpg)

**Paso 2. Descargar el código.** Pulsar el botón verde **Code**. Se despliega el menú con la pestaña **HTTPS** (URL para `git clone`), **GitHub CLI** y la opción **Download ZIP** (descarga sin Git). Copiar la URL HTTPS o descargar el ZIP.

![Menú Code: clonar por HTTPS o descargar ZIP](screens/gh2_download.jpg)

> **Autenticación en Git.** Para `git clone` por HTTPS, o para subir resultados (SARIF), inicie sesión en GitHub (botón *Sign in*) y, en la terminal, use `gh auth login` o un token de acceso personal. El clon anónimo de repos privados o tras un proxy puede fallar con `fatal: could not read Username for 'https://github.com'`.

# 16. Manual visual — Generar las opciones de Semgrep en la web

**Paso 1. Playground (editor de reglas).** En `https://semgrep.dev/playground` se construye una regla: a la izquierda el **patrón** (pestañas *search* / *taint*) y el bloque **Rule info** (Rule ID, **Language**, **Severity**, **Message**); a la derecha el **código de prueba** y el botón **Run** para ver las coincidencias en vivo.

![Semgrep Playground: generar/editar una regla](screens/sg1_playground.jpg)

**Paso 2. Registry (catálogo de opciones).** En `https://semgrep.dev/explore` se eligen rulesets listos: **owasp-top-ten**, **r2c-security-audit**, **cwe-top-25**, **default**, **secure-defaults**, etc. Cada tarjeta es una "opción" de configuración reutilizable.

![Semgrep Registry: rulesets disponibles](screens/sg2_registry.jpg)

**Paso 3. Opción generada (comando para la CLI).** Al abrir un ruleset (p. ej. **owasp-top-ten**) la web muestra el comando listo para copiar — *Test and run locally:* **`semgrep --config "p/owasp-top-ten"`** — y el botón **Use in CI**, además de filtros por **Language, Category, OWASP y Severity**. Así se "genera la opción" que luego se ejecuta localmente o en un flujo de CI.

![Ruleset owasp-top-ten: comando --config generado](screens/sg3_ruleset.jpg)

> **Nota.** El catálogo remoto (`--config p/...`) y la plataforma web requieren acceso a `semgrep.dev`. En entornos sin conexión, use el ruleset local `php-sast-rules.yml` de este laboratorio (secciones 4–5).

# 17. Ejecución comentada en terminal (Kali Linux)

Esta sección reproduce las **ejecuciones reales** de los comandos en una terminal de Kali, con su salida, para seguir el laboratorio paso a paso.

**Paso 1 — Instalar Semgrep y clonar bWAPP.** Se verifica la versión (1.183.0) y se descarga el código. Recuerde: clonar requiere **estar autenticado en Git**.

![Terminal Kali: instalación de Semgrep y clonado de bWAPP](screens/term1_setup.png)

```bash
pipx install semgrep                                   # instala Semgrep
semgrep --version                                      # 1.183.0
git clone --depth 1 https://github.com/raesene/bWAPP.git
ls bWAPP/app | head -6
```

**Paso 2 — Escanear el proyecto Core.** El *Scan Summary* resume el resultado: **103 hallazgos** sobre **183 archivos** con **14 reglas**.

![Terminal Kali: escaneo del proyecto Core](screens/term2_scan_core.png)

```bash
semgrep scan --config php-sast-rules.yml --metrics=off \
  --exclude admin --exclude soap bWAPP/app
```

**Paso 3 — Escanear `admin` y `soap`, filtrar por severidad y exportar.** `admin` arroja **3**, `soap` **32**; filtrando solo severidad alta (ERROR) en Core quedan **60**. Al final se exporta a **JSON** (para las gráficas) y **SARIF** (para CI/CD).

![Terminal Kali: admin, soap, filtro de severidad y exportación](screens/term3_scan_all.png)

```bash
semgrep scan --config php-sast-rules.yml --metrics=off bWAPP/app/admin   # 3 hallazgos
semgrep scan --config php-sast-rules.yml --metrics=off bWAPP/app/soap    # 32 hallazgos
# solo severidad alta (ERROR) del Core
semgrep scan --config php-sast-rules.yml --severity ERROR \
  --exclude admin --exclude soap bWAPP/app                               # 60 hallazgos
# exportar resultados
semgrep scan --config php-sast-rules.yml --json  -o core.json  bWAPP/app
semgrep scan --config php-sast-rules.yml --sarif -o core.sarif bWAPP/app
```

*Documento de apoyo docente. El análisis SAST se limita a bWAPP (aplicación de entrenamiento). El escaneo de código de terceros requiere autorización expresa.*
