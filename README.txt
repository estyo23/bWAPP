LABORATORIO SAST con Semgrep sobre bWAPP
Universidad Mariano Galvez - Diplomado en Ciberseguridad

CONTENIDO
  bWAPP-app/              Codigo PHP de bWAPP (3 carpetas: raiz, admin/, soap/)
  semgrep/php-sast-rules.yml  Ruleset local de Semgrep (14 reglas, OWASP/CWE)
  semgrep/analyze.py      Script que agrega hallazgos y genera las graficas
  semgrep/out/*.json      Salidas JSON de los 3 escaneos (ya incluidas)
  semgrep/summary.json    Resumen agregado
  charts/*.png            Las 5 graficas
  guia_sast.md            Fuente de la guia

REQUISITOS
  - Python 3.9+  y  Semgrep   (pip install semgrep  o  pipx install semgrep)
  - Para clonar bWAPP desde GitHub hay que estar AUTENTICADO en Git
    (gh auth login  o  token de acceso personal). Aqui el codigo ya viene incluido.

REPRODUCIR LOS ESCANEOS
  cd bwapp-sast-lab
  R=semgrep/php-sast-rules.yml
  OFF="--metrics=off --disable-version-check --no-git-ignore"
  semgrep scan --config $R $OFF --exclude admin --exclude soap --json -o semgrep/out/core.json  bWAPP-app
  semgrep scan --config $R $OFF --json -o semgrep/out/admin.json bWAPP-app/admin
  semgrep scan --config $R $OFF --json -o semgrep/out/soap.json  bWAPP-app/soap

REGENERAR LAS GRAFICAS (usa los JSON incluidos)
  pip install matplotlib
  python3 semgrep/analyze.py
