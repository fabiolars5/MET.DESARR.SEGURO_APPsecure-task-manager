# Secure Task Manager

**Asignatura:** Metodologías de Desarrollo Seguro  
**Autora:** Fabiola Rueda — 22370396

\---

\-

## Definición de la aplicación y cómo ejecutarla

### ¿Qué es Secure Task Manager?

Secure Task Manager es una aplicación web tipo gestor de tareas que permite a los usuarios registrarse, iniciar sesión y gestionar sus tareas personales de forma segura.

**Funcionalidades principales:**

* Registro de usuarios e inicio de sesión
* Creación, visualización, edición y eliminación de tareas
* Control de acceso individual por usuario

**Tecnologías utilizadas:**

* Backend: Python + Flask
* Base de datos: SQLite
* Contenerización: Docker

### 

### Cómo ejecutar la aplicación

La aplicación se ejecuta en un entorno contenerizado mediante Docker, lo que permite una ejecución sencilla, aislada y reproducible.

**Requisitos previos:**

* Tener Docker y Docker Compose instalados

**Pasos para ejecutar:**

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU\\\\\\\_USUARIO/TU\\\\\\\_REPO.git
cd TU\\\\\\\_REPO

# 2. Levantar la aplicación
docker compose up -d

# 3. Acceder en el navegador
# http://localhost:3000
```

Para detener la aplicación:

```bash
docker compose down
```

\---

### Estructura de Carpetas

.github/workflows/security.yml: Es el corazón de tu Pipeline de CI/CD. Aquí se definen las acciones automáticas que se ejecutan cada vez que subes código (como tests de seguridad, escaneo de vulnerabilidades o linters).

app/: Contiene el código fuente de la aplicación.

app.py: El archivo principal (backend) de la aplicación, probablemente usando Flask o un framework similar.

templates/: Archivos HTML para la interfaz de usuario (login, registro, tareas).

requirements.txt: Lista de librerías necesarias para que la app funcione.

docs/: Documentación teórica.

actividad1_memoria.md: Memoria técnica de la primera fase del proyecto.

plan_actividades_posteriores.md: Hoja de ruta para implementar mejoras de seguridad futuras.

tests/: Carpeta destinada a las pruebas automáticas para asegurar que el código no tiene errores antes de desplegarlo.

Dockerfile y docker-compose.yml: Archivos de Contenerización. Permiten que la aplicación se ejecute en cualquier ordenador dentro de un contenedor aislado, mejorando la seguridad y la portabilidad.

.gitignore: Archivo que le dice a Git qué archivos debe ignorar (como contraseñas, bases de datos locales o archivos temporales) para que no se suban por error al repositorio público.


