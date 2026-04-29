Actividad 2.2 + actividad 2.3 
# 📚 Sistema de Biblioteca - Seguridad Web

Este proyecto es una aplicación web de gestión de biblioteca diseñada con un enfoque pedagógico para demostrar la implementación de medidas de seguridad esenciales en el desarrollo frontend. La aplicación permite el registro de usuarios, inicio de sesión seguro y la visualización de un catálogo de libros.

## 🛡️ Características de Seguridad Implementadas

El sistema destaca por integrar las siguientes medidas de protección, utilizando estándares modernos de la industria:

* **Criptografía Nativa:** Uso de la **Web Crypto API** para procesos criptográficos en el navegador.
* **Hashing SHA-256:** Las contraseñas nunca se almacenan en texto plano; se utiliza el algoritmo SHA-256 para generar representaciones únicas e irreversibles.
* **Salting Individual:** Cada usuario cuenta con un *salt* (valor aleatorio) de 16 bytes único generado mediante `crypto.getRandomValues()`. Esto protege contra ataques de diccionario y *rainbow tables*.
* **Protección contra Fuerza Bruta:** Implementación de un límite de intentos (5) con bloqueo temporal de cuenta (30 segundos) tras múltiples fallos.
* **Sanitización de Datos (Anti-XSS):** Todas las entradas de usuario se escapan antes de ser renderizadas en el DOM para prevenir ataques de *Cross-Site Scripting*.
* **Gestión Segura de Sesiones:** Uso de cookies con los flags `SameSite=Strict` y `Secure` (en contextos HTTPS) para mitigar ataques CSRF y el secuestro de sesiones.
* **Validación de Fortaleza:** Sistema visual en tiempo real para asegurar que las contraseñas cumplan con requisitos de complejidad (longitud, mayúsculas, números y caracteres especiales).

## 🚀 Tecnologías Utilizadas

* **HTML5:** Estructura semántica del sistema.
* **CSS3:** Diseño responsivo y moderno utilizando la tipografía *Poppins*.
* **JavaScript (Vanilla):** Lógica de negocio, manejo del estado y cifrado. No depende de librerías externas para la seguridad.

## 📂 Estructura del Proyecto

```text
.
├── index.html   # Estructura de la aplicación y contenedores
├── style.css    # Definiciones de estilos y animaciones
└── script.js    # Lógica de autenticación, seguridad y catálogo
