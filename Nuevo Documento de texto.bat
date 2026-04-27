@echo off
:: Configurar codificación UTF-8 para tildes y caracteres especiales
chcp 65001 > nul

:: Definir la ruta específica
set "TARGET_DIR=C:\Users\fabio\Documents\---IMPORTANTE VIDA DIGITAL----\05_FORMACIÓN\GRADO ING CIBERSEGURIDAD - UEM\3ER AÑO 2025 - 2026\2DO SEMESTRE\9. METOD.DESARROLLO SEGURO\ACTIVIDADES\secure-task-manager"

:: Nombre del archivo de salida
set "OUTPUT=Estructura_Secure_Task_Manager.txt"

echo Generando listado de carpetas y documentos...

:: Entrar en la carpeta para que el árbol empiece desde ahí
pushd "%TARGET_DIR%"

:: Crear cabecera en el archivo
echo ESTRUCTURA DE PROYECTO: secure-task-manager > "%~dp0%OUTPUT%"
echo Generado el: %date% a las %time% >> "%~dp0%OUTPUT%"
echo. >> "%~dp0%OUTPUT%"

:: Ejecutar TREE ( /F para archivos, /A para formato de texto simple)
tree /F /A >> "%~dp0%OUTPUT%"

:: Volver a la carpeta original
popd

echo.
echo Proceso finalizado. Se ha creado: %OUTPUT%
pause