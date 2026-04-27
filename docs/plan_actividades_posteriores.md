# Plan para actividades posteriores

## Actividad 2 - DevSecOps

Se añadirá un pipeline en GitHub Actions con:
- Instalación de dependencias.
- SAST con Bandit.
- SCA con pip-audit.
- Construcción de imagen Docker.
- Pruebas básicas.

## Actividad 3 - Herramientas automáticas

Se podrán introducir vulnerabilidades controladas en una rama o carpeta específica:
- SQL Injection intencionada.
- XSS intencionado.
- Dependencia vulnerable.
- Secreto falso para detectar exposición.
- Configuración Docker insegura.

Herramientas candidatas:
- Bandit.
- pip-audit.
- OWASP ZAP.
- Nmap.
- Trivy o Docker Scout.
- GitHub Dependabot / CodeQL.

## Actividad 4 - Riesgos y OWASP

Las vulnerabilidades detectadas se clasificarán con OWASP Top 10:
- A01 Broken Access Control.
- A02 Cryptographic Failures.
- A03 Injection.
- A05 Security Misconfiguration.
- A06 Vulnerable and Outdated Components.
