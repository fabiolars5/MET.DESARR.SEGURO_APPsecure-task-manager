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



