# applied-cryptography-network-security
Este repositorio contiene implementaciones avanzadas de protocolos de comunicación segura y gestión de identidades, desarrolladas en Python. El enfoque principal es la aplicación práctica de criptografía híbrida y la seguridad en capas de transporte (TLS).

## Proyectos Destacados

### 1. PKI & Hybrid Cryptography (Alice & Bob)
Simulación de un entorno de comunicación segura de extremo a extremo (E2EE). 
* **Funcionamiento:** Utiliza **RSA** para el intercambio seguro de claves y **AES** para el cifrado de la sesión.
* **Componentes:** Incluye la lógica de una Autoridad Certificadora (CA) para la validación de identidades mediante certificados.
* **Carpeta:** `/01-pki-hybrid-communication`

### 2. Key Distribution Center (KDC) Protocol
Implementación de un protocolo de distribución de claves simétricas inspirado en Needham-Schroeder (base de Kerberos).
* **Objetivo:** Establecer una clave de sesión segura entre dos nodos a través de un tercero de confianza (Trusted Third Party).
* **Seguridad:** Uso de *nonces* para prevenir ataques de replicación (replay attacks).
* **Carpeta:** `/02-kdc-auth-protocol`

### 3. HTTPS Server & TLS Analysis
Desarrollo de servidores web seguros con soporte para protocolos de cifrado modernos.
* **Habilidades:** Configuración de contextos SSL/TLS en Python y gestión de certificados X.509.
* **Análisis:** Incluye capturas de tráfico (.pcapng) para el estudio del Handshake TLS y la negociación de algoritmos de cifrado.
* **Carpeta:** `/03-https-tls-server`

## Stack Tecnológico
* **Lenguaje:** Python 3.x
* **Librerías:** PyCryptodome (AES, RSA, HMAC), SSL, Sockets.
* **Herramientas de Análisis:** Wireshark (Análisis de flujos TLS).
