/* =============================================
   CONSTANTES Y ESTADO GLOBAL
============================================= */
const MAX_INTENTOS = 5;
const SESSION_MIN  = 30;
const COOKIE_NAME  = 'bib_sess';

let usuarioActivo    = null;
let intentosFallidos = 0;
let bloqueadoHasta   = null;
let usuariosDB       = [];

const libros = [
  { titulo:"Cien Años de Soledad",  autor:"Gabriel García Márquez",  genero:"Realismo Mágico", anio:1967, disponible:true  },
  { titulo:"1984",                  autor:"George Orwell",            genero:"Distopía",        anio:1949, disponible:false },
  { titulo:"El Principito",         autor:"Antoine de Saint-Exupéry", genero:"Fábula",          anio:1943, disponible:true  },
  { titulo:"Don Quijote",           autor:"Miguel de Cervantes",      genero:"Novela",          anio:1605, disponible:true  }
];

/* =============================================
   INICIALIZACIÓN
============================================= */
window.addEventListener('DOMContentLoaded', async () => {
  renderIntentoDots();
  verificarHTTPS();
  await crearUsuariosIniciales();
  verificarSesionGuardada();
});

function verificarHTTPS() {
  if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    document.getElementById('httpsWarn').style.display = 'block';
  } else {
    const b = document.getElementById('badgeHTTPS');
    b.textContent = '✓ HTTPS activo';
    b.className = 'badge green';
  }
}

/* =============================================
   CRIPTOGRAFÍA — Web Crypto API nativa
============================================= */
function generarSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const datos   = encoder.encode(salt + password);
  const buffer  = await crypto.subtle.digest('SHA-256', datos);
  return Array.from(new Uint8Array(buffer))
              .map(b => b.toString(16).padStart(2,'0')).join('');
}

/* =============================================
   SANITIZACIÓN (Anti-XSS)
============================================= */
function sanitizar(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

/* =============================================
   GESTIÓN DE COOKIES (Sesión segura)
============================================= */
function setCookie(nombre, valor, minutos) {
  const expira = new Date(Date.now() + minutos * 60000).toUTCString();
  const secure = location.protocol === 'https:' ? ';Secure' : '';
  document.cookie = `${nombre}=${encodeURIComponent(valor)};expires=${expira};path=/;SameSite=Strict${secure}`;
}

function getCookie(nombre) {
  const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + nombre + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function deleteCookie(nombre) {
  document.cookie = `${nombre}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;SameSite=Strict`;
}

/* =============================================
   USUARIOS INICIALES
============================================= */
async function crearUsuariosIniciales() {
  const s1 = generarSalt(), s2 = generarSalt();
  usuariosDB = [
    { usuario:'admin', hash: await hashPassword('Admin@123', s1), salt:s1, rol:'Administrador' },
    { usuario:'juanjosex69',  hash: await hashPassword('Juan@2024', s2), salt:s2, rol:'Usuario'        }
  ];
  console.info('[Seguridad] Usuarios cargados con SHA-256 + salt individual.');
}

/* =============================================
   VALIDACIÓN DE CONTRASEÑA EN TIEMPO REAL
============================================= */
const REGLAS = {
  len    : p => p.length >= 8,
  upper  : p => /[A-Z]/.test(p),
  lower  : p => /[a-z]/.test(p),
  num    : p => /[0-9]/.test(p),
  special: p => /[!@#$%^&*()\-_=+\[\]{};:'",.<>/?\\|`~]/.test(p)
};

function calcularFuerza(p) {
  return Object.values(REGLAS).filter(fn => fn(p)).length;
}

function validarFuerza() {
  const p = document.getElementById('regClave').value;
  const f = calcularFuerza(p);

  document.getElementById('req-len').className     = REGLAS.len(p)     ? 'ok' : '';
  document.getElementById('req-upper').className   = REGLAS.upper(p)   ? 'ok' : '';
  document.getElementById('req-lower').className   = REGLAS.lower(p)   ? 'ok' : '';
  document.getElementById('req-num').className     = REGLAS.num(p)     ? 'ok' : '';
  document.getElementById('req-special').className = REGLAS.special(p) ? 'ok' : '';

  const colores   = ['','#ef4444','#f59e0b','#f59e0b','#22c55e','#22c55e'];
  const etiquetas = ['Ingresa una contraseña','Muy débil','Débil','Aceptable','Fuerte','Muy fuerte'];
  for (let i = 1; i <= 4; i++) {
    document.getElementById('sb'+i).style.background = i <= f ? colores[f] : '#e5e7eb';
  }
  document.getElementById('strengthLabel').textContent = p.length === 0 ? etiquetas[0] : etiquetas[f];
}

function validarCampoUsuario() {
  const u = document.getElementById('regUsuario');
  u.className = u.value.length >= 4 ? 'input-ok' : 'input-error';
}

function validarConfirmacion() {
  const p  = document.getElementById('regClave').value;
  const c2 = document.getElementById('regClaveConf');
  c2.className = (c2.value === p && p.length > 0) ? 'input-ok' : 'input-error';
}

function mostrarMensaje(id, texto, tipo) {
  const el = document.getElementById(id);
  el.textContent = texto;
  el.className = tipo ? `msg ${tipo}` : 'msg';
}

/* =============================================
   REGISTRO DE USUARIO
============================================= */
async function registrarUsuario() {
  const u  = sanitizar(document.getElementById('regUsuario').value.trim());
  const p  = document.getElementById('regClave').value;
  const p2 = document.getElementById('regClaveConf').value;

  if (u.length < 4) return mostrarMensaje('mensajeRegistro', '⚠ El usuario debe tener al menos 4 caracteres.', 'error');
  if (usuariosDB.find(x => x.usuario === u)) return mostrarMensaje('mensajeRegistro', '⚠ Ese nombre de usuario ya existe.', 'error');
  if (calcularFuerza(p) < 4) return mostrarMensaje('mensajeRegistro', '⚠ La contraseña no cumple los requisitos mínimos de seguridad.', 'error');
  if (p !== p2) return mostrarMensaje('mensajeRegistro', '⚠ Las contraseñas no coinciden.', 'error');

  const salt = generarSalt();
  const hash = await hashPassword(p, salt);
  usuariosDB.push({ usuario: u, hash, salt, rol: 'Usuario' });

  console.info(`[Seguridad] Usuario '${u}' registrado. Hash: ${hash.slice(0,16)}... Salt: ${salt.slice(0,8)}...`);
  mostrarMensaje('mensajeRegistro', '✅ Cuenta creada exitosamente. ¡Ya puedes iniciar sesión!', 'success');

  setTimeout(() => {
    document.getElementById('regUsuario').value   = '';
    document.getElementById('regClave').value     = '';
    document.getElementById('regClaveConf').value = '';
    mostrarMensaje('mensajeRegistro', '', '');
    cambiarTab('login');
  }, 1800);
}

/* =============================================
   INICIO DE SESIÓN
============================================= */
async function iniciarSesion() {
  if (bloqueadoHasta && Date.now() < bloqueadoHasta) {
    const seg = Math.ceil((bloqueadoHasta - Date.now()) / 1000);
    return mostrarMensaje('mensajeLogin', `🔒 Cuenta bloqueada. Espera ${seg}s antes de intentar nuevamente.`, 'error');
  }

  const u = sanitizar(document.getElementById('usuario').value.trim());
  const p = document.getElementById('clave').value;

  if (!u || !p) return mostrarMensaje('mensajeLogin', '⚠ Completa todos los campos.', 'warning');

  const encontrado = usuariosDB.find(x => x.usuario === u);
  let credOk = false;

  if (encontrado) {
    const hashIntento = await hashPassword(p, encontrado.salt);
    credOk = hashIntento === encontrado.hash;
  }

  if (credOk) {
    intentosFallidos = 0;
    bloqueadoHasta   = null;
    renderIntentoDots();
    usuarioActivo = encontrado;

    const sessionId = generarSalt();
    const payload   = JSON.stringify({
      usuario: encontrado.usuario, rol: encontrado.rol,
      expiry: Date.now() + SESSION_MIN * 60000, sessionId
    });
    setCookie(COOKIE_NAME, payload, SESSION_MIN);
    console.info('[Seguridad] Sesión iniciada. Cookie SameSite=Strict. ID:', sessionId.slice(0,8));
    mostrarCatalogo(encontrado, sessionId);

  } else {
    intentosFallidos++;
    renderIntentoDots();
    const restantes = MAX_INTENTOS - intentosFallidos;

    if (intentosFallidos >= MAX_INTENTOS) {
      bloqueadoHasta = Date.now() + 30000;
      document.getElementById('btnLogin').disabled = true;
      mostrarMensaje('mensajeLogin', '🔒 Demasiados intentos fallidos. Bloqueado por 30 segundos.', 'error');
      setTimeout(() => {
        bloqueadoHasta = null;
        intentosFallidos = 0;
        document.getElementById('btnLogin').disabled = false;
        renderIntentoDots();
        mostrarMensaje('mensajeLogin', 'Ya puedes intentar nuevamente.', 'warning');
      }, 30000);
    } else {
      mostrarMensaje('mensajeLogin', `❌ Credenciales incorrectas. ${restantes} intento${restantes !== 1 ? 's' : ''} restante${restantes !== 1 ? 's' : ''}.`, 'error');
    }
  }
}

function renderIntentoDots() {
  const cont = document.getElementById('intentosDots');
  cont.innerHTML = '';
  for (let i = 0; i < MAX_INTENTOS; i++) {
    const d = document.createElement('div');
    d.className = 'attempt-dot' + (i < intentosFallidos ? ' used' : '');
    cont.appendChild(d);
  }
}

/* =============================================
   VERIFICAR COOKIE
============================================= */
function verificarSesionGuardada() {
  const raw = getCookie(COOKIE_NAME);
  if (!raw) return;
  try {
    const sesion = JSON.parse(raw);
    if (Date.now() > sesion.expiry) { deleteCookie(COOKIE_NAME); return; }
    const user = usuariosDB.find(u => u.usuario === sesion.usuario);
    if (user) { usuarioActivo = user; mostrarCatalogo(user, sesion.sessionId, true); }
  } catch { deleteCookie(COOKIE_NAME); }
}

/* =============================================
   CATÁLOGO
============================================= */
function mostrarCatalogo(user, sessionId, desde_cookie = false) {
  document.getElementById('loginSeccion').style.display    = 'none';
  document.getElementById('catalogoSeccion').style.display = 'block';
  document.getElementById('nombreUsuario').textContent     = sanitizar(user.usuario);
  document.getElementById('rolUsuario').textContent        = sanitizar(user.rol);
  document.getElementById('sessionId').textContent         = sessionId.slice(0,12) + '…';
  document.getElementById('sessionExpiry').textContent     = SESSION_MIN;
  mostrarLibros(libros);
  if (!desde_cookie) {
    document.getElementById('usuario').value = '';
    document.getElementById('clave').value   = '';
  }
}

function cerrarSesion() {
  deleteCookie(COOKIE_NAME);
  usuarioActivo = null;
  document.getElementById('loginSeccion').style.display    = 'block';
  document.getElementById('catalogoSeccion').style.display = 'none';
  mostrarMensaje('mensajeLogin', '', '');
  console.info('[Seguridad] Sesión cerrada. Cookie eliminada.');
}

function mostrarLibros(lista) {
  const tbody = document.getElementById('tablaLibros');
  tbody.innerHTML = '';
  lista.forEach(libro => {
    tbody.innerHTML += `<tr>
      <td><strong>${sanitizar(libro.titulo)}</strong></td>
      <td>${sanitizar(libro.autor)}</td>
      <td>${sanitizar(libro.genero)}</td>
      <td>${sanitizar(libro.anio)}</td>
      <td>${libro.disponible ? '✅ Disponible' : '❌ Prestado'}</td>
    </tr>`;
  });
}

function buscarLibros() {
  const texto = sanitizar(document.getElementById('busqueda').value.toLowerCase());
  mostrarLibros(libros.filter(l =>
    l.titulo.toLowerCase().includes(texto) ||
    l.autor.toLowerCase().includes(texto)  ||
    l.genero.toLowerCase().includes(texto)
  ));
}

/* =============================================
   TABS
============================================= */
function cambiarTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'registro' && i === 1));
  });
  document.getElementById('tab-login').classList.toggle('active',    tab === 'login');
  document.getElementById('tab-registro').classList.toggle('active', tab === 'registro');
}
