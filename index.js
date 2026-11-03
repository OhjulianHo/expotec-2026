
require('dotenv').config();

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { ObjectId } = require('mongodb');

const conectarBD = require('./conexion');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRETO = process.env.JWT_SECRET;

// =====================================================
// CONFIGURACIÓN DE DOCUMENTOS PRIVADOS
// =====================================================

const carpetaDocumentos = path.join(
  __dirname,
  'documentos-privados'
);

fs.mkdirSync(carpetaDocumentos, { recursive: true });

const almacenamientoDocumentos = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, carpetaDocumentos);
  },

  filename: (req, file, cb) => {
    const extensionesPermitidas = {
      'application/pdf': '.pdf',
      'image/jpeg': '.jpg',
      'image/png': '.png'
    };

    const extension = extensionesPermitidas[file.mimetype];

    if (!extension) {
      return cb(
        new Error('Solo se permiten archivos PDF, JPG o PNG')
      );
    }

    const nombreSeguro =
      `${Date.now()}-${crypto.randomBytes(16).toString('hex')}`;

    cb(null, nombreSeguro + extension);
  }
});

const subirDocumentos = multer({
  storage: almacenamientoDocumentos,

  limits: {
    files: 2,
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const tiposPermitidos = [
      'application/pdf',
      'image/jpeg',
      'image/png'
    ];

    if (!tiposPermitidos.includes(file.mimetype)) {
      return cb(
        new Error('Formato no permitido. Usa PDF, JPG o PNG.')
      );
    }

    cb(null, true);
  }
});

// =====================================================
// CONFIGURACIÓN DEL CORREO
// =====================================================

const transporter = nodemailer.createTransport({
  service: 'gmail',

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

// Los documentos privados NO están dentro de public.
app.use(express.static(path.join(__dirname, 'public')));

// =====================================================
// PÁGINA PRINCIPAL
// =====================================================

app.get('/', (req, res) => {
  res.redirect('/indexamaeno.html');
});

// =====================================================
// VERIFICACIÓN DEL TOKEN JWT
// =====================================================

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Token requerido'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, SECRETO);

    if (!ObjectId.isValid(decoded.id)) {
      return res.status(403).json({
        error: 'Token inválido'
      });
    }

    req.usuarioId = new ObjectId(decoded.id);
    next();
  } catch (error) {
    return res.status(403).json({
      error: 'Token inválido o expirado'
    });
  }
}

// =====================================================
// CÓDIGOS DE VERIFICACIÓN POR CORREO
// =====================================================

const DURACION_CODIGO_MS = 10 * 60 * 1000;

function generarCodigoOTP() {
  return crypto.randomInt(0, 1000000)
    .toString()
    .padStart(6, '0');
}

function hashCodigo(codigo) {
  return crypto
    .createHash('sha256')
    .update(codigo)
    .digest('hex');
}

async function enviarCodigoCorreo(email, codigo) {
  return transporter.sendMail({
    from: `"Amaeno" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verifica tu correo electrónico - Amaeno',

    text:
      `Tu código de verificación es: ${codigo}. ` +
      'Caduca en 10 minutos.',

    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;padding:25px;color:#333">
        <h1 style="color:#ed8b3a">Amaeno</h1>
        <h2>Verifica tu correo electrónico</h2>
        <p>Utiliza el siguiente código para completar tu registro:</p>
        <div style="font-size:34px;font-weight:bold;letter-spacing:8px;background:#f7f2ed;padding:20px;text-align:center;border-radius:12px;color:#ed8b3a">
          ${codigo}
        </div>
        <p>Este código caduca en 10 minutos.</p>
        <p>Si no solicitaste este registro, ignora este mensaje.</p>
      </div>
    `
  });
}

app.post(
  '/api/registro-psicologo',

  subirDocumentos.fields([
    { name: 'cedula', maxCount: 1 },
    { name: 'certificado', maxCount: 1 }
  ]),

  async (req, res) => {
    try {
      const { nombre, apellidos, email, clave } = req.body;

      if (
        typeof nombre !== 'string' ||
        typeof apellidos !== 'string' ||
        typeof email !== 'string' ||
        typeof clave !== 'string' ||
        !nombre.trim() ||
        !apellidos.trim() ||
        !email.trim() ||
        !clave
      ) {
        return res.status(400).json({
          error: 'Completa todos los campos obligatorios'
        });
      }

      if (clave.length < 8) {
        return res.status(400).json({
          error: 'La contraseña debe tener al menos 8 caracteres'
        });
      }

      const archivos = req.files || {};
      const archivoCedula = archivos.cedula?.[0];
      const archivoCertificado = archivos.certificado?.[0];

      if (!archivoCedula || !archivoCertificado) {
        return res.status(400).json({
          error: 'Debes adjuntar la cédula y el certificado profesional'
        });
      }

      const emailNormalizado = email.trim().toLowerCase();
      const db = await conectarBD();

      const usuarios = db.collection('usuarios');
      const verificaciones = db.collection('verificaciones_email');

      const existente = await usuarios.findOne({
        email: emailNormalizado
      });

      if (existente) {
        return res.status(409).json({
          error: 'El correo electrónico ya está registrado'
        });
      }

      const codigo = generarCodigoOTP();
      const codigoHash = hashCodigo(codigo);
      const hashClave = await bcrypt.hash(clave, 10);

      // Enviar el correo antes de guardar la solicitud pendiente.
      await enviarCodigoCorreo(emailNormalizado, codigo);

      await verificaciones.updateOne(
        { email: emailNormalizado },

        {
          $set: {
            nombre: nombre.trim(),
            apellidos: apellidos.trim(),
            email: emailNormalizado,
            clave: hashClave,
            rol: 'psicologo',

            documentos: {
              cedula: archivoCedula.filename,
              certificado: archivoCertificado.filename
            },

            codigoHash,
            expiraEn: new Date(Date.now() + DURACION_CODIGO_MS),
            intentos: 0,
            creadoEn: new Date()
          }
        },

        { upsert: true }
      );

      return res.status(200).json({
        mensaje: 'Código de verificación enviado al correo electrónico'
      });
    } catch (error) {
      console.error('Error en registro de psicólogo:', error);

      return res.status(500).json({
        error: 'No se pudo iniciar el registro del psicólogo'
      });
    }
  }
);

app.post('/api/registro', async (req, res) => {
  try {
    const { nombre, email, clave } = req.body;

    if (
      typeof nombre !== 'string' ||
      typeof email !== 'string' ||
      typeof clave !== 'string' ||
      !nombre.trim() ||
      !email.trim() ||
      !clave
    ) {
      return res.status(400).json({
        error: 'Todos los campos son obligatorios'
      });
    }

    if (clave.length < 8) {
      return res.status(400).json({
        error: 'La contraseña debe tener al menos 8 caracteres'
      });
    }

    const emailNormalizado = email.trim().toLowerCase();
    const db = await conectarBD();

    const usuarios = db.collection('usuarios');
    const verificaciones = db.collection('verificaciones_email');

    const existente = await usuarios.findOne({
      email: emailNormalizado
    });

    if (existente) {
      return res.status(409).json({
        error: 'El correo electrónico ya está registrado'
      });
    }

    const codigo = generarCodigoOTP();
    const codigoHash = hashCodigo(codigo);
    const hashClave = await bcrypt.hash(clave, 10);

    await enviarCodigoCorreo(emailNormalizado, codigo);

    await verificaciones.updateOne(
      { email: emailNormalizado },

      {
        $set: {
          nombre: nombre.trim(),
          email: emailNormalizado,
          clave: hashClave,
          rol: 'paciente',
          codigoHash,
          expiraEn: new Date(Date.now() + DURACION_CODIGO_MS),
          intentos: 0,
          creadoEn: new Date()
        }
      },

      { upsert: true }
    );

    return res.status(200).json({
      mensaje: 'Código de verificación enviado al correo electrónico'
    });
  } catch (error) {
    console.error('Error en registro:', error);

    return res.status(500).json({
      error: 'No se pudo iniciar el registro o enviar el correo'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, clave } = req.body;

    if (
      typeof email !== 'string' ||
      typeof clave !== 'string' ||
      !email.trim() ||
      !clave
    ) {
      return res.status(400).json({
        error: 'Correo y contraseña son obligatorios'
      });
    }

    const db = await conectarBD();

    const usuario = await db.collection('usuarios').findOne({
      email: email.trim().toLowerCase()
    });

    if (!usuario) {
      return res.status(401).json({
        error: 'Credenciales inválidas'
      });
    }

    const passwordOk = await bcrypt.compare(clave, usuario.clave);

    if (!passwordOk) {
      return res.status(401).json({
        error: 'Credenciales inválidas'
      });
    }

    if (usuario.verificado !== true) {
      return res.status(403).json({
        error: 'Debes verificar tu correo electrónico antes de iniciar sesión'
      });
    }

    const token = jwt.sign(
      {
        id: usuario._id.toString(),
        email: usuario.email,
        rol: usuario.rol || 'paciente'
      },
      SECRETO,
      { expiresIn: '8h' }
    );

    return res.json({
      mensaje: 'Inicio de sesión exitoso',
      token,

      usuario: {
        id: usuario._id.toString(),
        nombre: usuario.nombre,
        apellidos: usuario.apellidos || '',
        email: usuario.email,
        rol: usuario.rol || 'paciente',
        estadoProfesional: usuario.estadoProfesional || null
      }
    });
  } catch (error) {
    console.error('Error en login:', error);

    return res.status(500).json({
      error: 'Error en el servidor'
    });
  }
});

app.post('/api/verificar-codigo', async (req, res) => {
  try {
    const { email, codigo } = req.body;

    if (
      typeof email !== 'string' ||
      typeof codigo !== 'string' ||
      !/^\d{6}$/.test(codigo)
    ) {
      return res.status(400).json({
        error: 'Correo o código inválido'
      });
    }

    const emailNormalizado = email.trim().toLowerCase();
    const db = await conectarBD();

    const verificaciones = db.collection('verificaciones_email');

    const pendiente = await verificaciones.findOne({
      email: emailNormalizado
    });

    if (!pendiente) {
      return res.status(400).json({
        error: 'No existe una verificación pendiente para este correo'
      });
    }

    if (new Date(pendiente.expiraEn) <= new Date()) {
      await verificaciones.deleteOne({
        _id: pendiente._id
      });

      return res.status(400).json({
        error: 'El código ha caducado. Regístrate nuevamente.'
      });
    }

    if (hashCodigo(codigo) !== pendiente.codigoHash) {
      return res.status(400).json({
        error: 'El código de verificación es incorrecto'
      });
    }

    const usuarios = db.collection('usuarios');

    const existente = await usuarios.findOne({
      email: emailNormalizado
    });

    if (existente) {
      await verificaciones.deleteOne({
        _id: pendiente._id
      });

      return res.status(409).json({
        error: 'El correo electrónico ya está registrado'
      });
    }

    const nuevoUsuario = {
      nombre: pendiente.nombre,
      email: emailNormalizado,
      clave: pendiente.clave,
      rol: pendiente.rol || 'paciente',
      verificado: true,
      fechaRegistro: new Date()
    };

    if (pendiente.rol === 'psicologo') {
      nuevoUsuario.apellidos = pendiente.apellidos;
      nuevoUsuario.documentos = pendiente.documentos;
      nuevoUsuario.estadoProfesional = 'pendiente';
    }

    await usuarios.insertOne(nuevoUsuario);

    await verificaciones.deleteOne({
      _id: pendiente._id
    });

    console.log(
      'Cuenta creada y correo verificado:',
      emailNormalizado
    );

    return res.json({
      mensaje: 'Correo verificado y cuenta creada correctamente'
    });
  } catch (error) {
    console.error('Error al verificar código:', error);

    return res.status(500).json({
      error: 'No se pudo verificar el código'
    });
  }
});

app.get('/api/usuario-logueado', verificarToken, async (req, res) => {
  try {
    const db = await conectarBD();

    const usuario = await db.collection('usuarios').findOne(
      { _id: req.usuarioId },
      {
        projection: {
          clave: 0
        }
      }
    );

    if (!usuario) {
      return res.status(404).json({
        error: 'Usuario no encontrado'
      });
    }

    return res.json({
      ...usuario,
      _id: usuario._id.toString()
    });
  } catch (error) {
    console.error('Error al obtener usuario:', error);

    return res.status(500).json({
      error: 'Error al obtener datos del usuario'
    });
  }
});
//aefiqefvbhkqfkqfjefkefkkbk<srbjkkesixsevenaqbvbqgbhbqegbheg

/* =====================================================
   CALENDARIO EMOCIONAL PERSONALIZADO
   ===================================================== */

// Obtener los registros del usuario autenticado
app.get('/api/calendario', verificarToken, async (req, res) => {
  try {
    const db = await conectarBD();

    const calendario = await db.collection('calendarios_emocionales')
      .findOne({ usuarioId: req.usuarioId });

    return res.json({
      registros: calendario?.registros || {}
    });
  } catch (error) {
    console.error('Error al obtener el calendario:', error);

    return res.status(500).json({
      error: 'No se pudo cargar el calendario emocional'
    });
  }
});

// Guardar los registros del usuario autenticado
app.put('/api/calendario', verificarToken, async (req, res) => {
  try {
    const { registros } = req.body;

    if (
      !registros ||
      typeof registros !== 'object' ||
      Array.isArray(registros)
    ) {
      return res.status(400).json({
        error: 'Los registros del calendario no son válidos'
      });
    }

    const db = await conectarBD();

    await db.collection('calendarios_emocionales').updateOne(
      { usuarioId: req.usuarioId },
      {
        $set: {
          registros,
          actualizadoEn: new Date()
        },
        $setOnInsert: {
          usuarioId: req.usuarioId,
          creadoEn: new Date()
        }
      },
      { upsert: true }
    );

    return res.json({
      mensaje: 'Calendario guardado correctamente'
    });
  } catch (error) {
    console.error('Error al guardar el calendario:', error);

    return res.status(500).json({
      error: 'No se pudo guardar el calendario emocional'
    });
  }
});

//MANAGER SQUIRE

app.get('/api/slots', verificarToken, async (req, res) => {
  try {
    const db = await conectarBD();

    const slots = await db.collection('save_slots')
      .find({ usuarioId: req.usuarioId })
      .sort({ numeroSlot: 1 })
      .toArray();

    const slotsJSON = slots.map(slot => ({
      ...slot,
      _id: slot._id.toString(),
      usuarioId: slot.usuarioId.toString()
    }));

    return res.json(slotsJSON);
  } catch (error) {
    console.error('Error al obtener partidas:', error);

    return res.status(500).json({
      error: 'Error al obtener las partidas guardadas'
    });
  }
});

app.post('/api/slots', verificarToken, async (req, res) => {
  try {
    const { numeroSlot, resumen, datosRpgMaker, savefileInfo } = req.body;
    const numero = Number(numeroSlot);

    if (!Number.isInteger(numero) || numero < 1 || numero > 100) {
      return res.status(400).json({
        error: 'El número de slot no es válido'
      });
    }

    if (resumen === undefined || datosRpgMaker === undefined) {
      return res.status(400).json({
        error: 'Faltan datos de la partida'
      });
    }

    const db = await conectarBD();
    const slots = db.collection('save_slots');

    const resumenStr =
      typeof resumen === 'object' && resumen !== null
        ? JSON.stringify(resumen)
        : String(resumen);

    const filtro = {
      usuarioId: req.usuarioId,
      numeroSlot: numero
    };

    const datosActualizados = {
  resumen: resumenStr,
  datosRpgMaker,
  savefileInfo: savefileInfo || null,
  fechaGuardado: new Date()
};

    await slots.updateOne(
      filtro,
      {
        $set: datosActualizados,

        $setOnInsert: {
          usuarioId: req.usuarioId,
          numeroSlot: numero
        }
      },
      { upsert: true }
    );

    const slot = await slots.findOne(filtro);

    return res.status(200).json({
      mensaje: 'Partida guardada exitosamente',

      slot: {
        ...slot,
        _id: slot._id.toString(),
        usuarioId: slot.usuarioId.toString()
      }
    });
  } catch (error) {
    console.error('Error al guardar slot:', error);

    return res.status(500).json({
      error: 'Error al guardar la partida en la base de datos'
    });
  }
});

app.get('/api/slots/:numeroSlot', verificarToken, async (req, res) => {
  try {
    const numero = Number(req.params.numeroSlot);

    if (!Number.isInteger(numero) || numero < 1 || numero > 100) {
      return res.status(400).json({
        error: 'El número de slot no es válido'
      });
    }

    const db = await conectarBD();

    const slot = await db.collection('save_slots').findOne({
      usuarioId: req.usuarioId,
      numeroSlot: numero
    });

    if (!slot) {
      return res.status(404).json({
        error: 'Slot de guardado vacío'
      });
    }

    return res.json({
      ...slot,
      _id: slot._id.toString(),
      usuarioId: slot.usuarioId.toString()
    });
  } catch (error) {
    console.error('Error al cargar slot:', error);

    return res.status(500).json({
      error: 'Error al cargar el slot'
    });
  }
});

app.delete('/api/slots/:numeroSlot', verificarToken, async (req, res) => {
  try {
    const numero = Number(req.params.numeroSlot);

    if (!Number.isInteger(numero) || numero < 1 || numero > 100) {
      return res.status(400).json({
        error: 'El número de slot no es válido'
      });
    }

    const db = await conectarBD();

    const resultado = await db.collection('save_slots').deleteOne({
      usuarioId: req.usuarioId,
      numeroSlot: numero
    });

    if (resultado.deletedCount === 0) {
      return res.status(404).json({
        error: 'No hay partida para eliminar en este slot'
      });
    }

    return res.json({
      mensaje: `Partida del Slot ${numero} eliminada correctamente`
    });
  } catch (error) {
    console.error('Error al borrar slot:', error);

    return res.status(500).json({
      error: 'Error al borrar el slot'
    });
  }
});
//WILD HUNT AKJBAKEKBEAWVBAEKJVB

/* =========================================
   FORO AMAENO
   ========================================= */

// Comprueba el rol consultando MongoDB.
// No confiamos en el rol guardado en localStorage.
async function verificarPsicologo(req, res, next) {
    try {
        const db = await conectarBD();

        const usuario = await db.collection('usuarios').findOne({
            _id: req.usuarioId
        });

        if (!usuario) {
            return res.status(401).json({
                error: 'Usuario no encontrado'
            });
        }

        const rol = String(usuario.rol || '').toLowerCase().trim();

        if (!['psicologo', 'psychologist'].includes(rol)) {
            return res.status(403).json({
                error: 'Solo los psicólogos pueden publicar en el foro'
            });
        }

        req.usuarioForo = usuario;
        next();
    } catch (error) {
        console.error('Error verificando al psicólogo:', error);
        return res.status(500).json({
            error: 'No se pudo verificar el permiso'
        });
    }
}


// Obtiene todas las publicaciones para la comunidad.
// Los usuarios comunes pueden consultar esta ruta.
app.get('/api/posts', async (req, res) => {
    try {
        const db = await conectarBD();

        const posts = await db.collection('foro_posts')
            .find({})
            .sort({ creadoEn: -1 })
            .toArray();

        res.json(posts);
    } catch (error) {
        console.error('Error cargando publicaciones:', error);
        res.status(500).json({
            error: 'No se pudieron cargar las publicaciones'
        });
    }
});


// Obtiene únicamente las publicaciones del psicólogo autenticado.
app.get(
    '/api/posts/mis-posts',
    verificarToken,
    verificarPsicologo,
    async (req, res) => {
        try {
            const db = await conectarBD();

            const posts = await db.collection('foro_posts')
                .find({ autorId: req.usuarioId })
                .sort({ creadoEn: -1 })
                .toArray();

            res.json(posts);
        } catch (error) {
            console.error('Error cargando mis publicaciones:', error);
            res.status(500).json({
                error: 'No se pudieron cargar tus publicaciones'
            });
        }
    }
);


// Crear una publicación.
app.post(
    '/api/posts',
    verificarToken,
    verificarPsicologo,
    async (req, res) => {
        try {
            const {
                titulo,
                provincia,
                fecha,
                imagen,
                descripcion
            } = req.body;

            if (
                typeof titulo !== 'string' ||
                typeof provincia !== 'string' ||
                typeof fecha !== 'string' ||
                typeof descripcion !== 'string' ||
                !titulo.trim() ||
                !provincia.trim() ||
                !fecha.trim() ||
                !descripcion.trim()
            ) {
                return res.status(400).json({
                    error: 'Completa todos los campos obligatorios'
                });
            }

            const provinciasPermitidas = [
                'San José',
                'Alajuela',
                'Cartago',
                'Heredia',
                'Guanacaste',
                'Puntarenas',
                'Limón'
            ];

            if (!provinciasPermitidas.includes(provincia)) {
                return res.status(400).json({
                    error: 'La provincia no es válida'
                });
            }

            if (
                titulo.trim().length > 150 ||
                descripcion.trim().length > 10000
            ) {
                return res.status(400).json({
                    error: 'El título o la descripción son demasiado largos'
                });
            }

            const db = await conectarBD();
            const usuario = req.usuarioForo;

            const nombreCompleto = [
                usuario.nombre,
                usuario.apellidos
            ].filter(Boolean).join(' ').trim();

            const iniciales = nombreCompleto
                .split(/\s+/)
                .filter(Boolean)
                .slice(0, 2)
                .map(palabra => palabra[0].toUpperCase())
                .join('');

            const nuevaPublicacion = {
                titulo: titulo.trim(),
                provincia,
                fecha: fecha.trim(),
                imagen: typeof imagen === 'string' ? imagen.trim() : '',
                descripcion: descripcion.trim(),

                // Identidad tomada de la cuenta autenticada.
                autorId: req.usuarioId,
                nombre: nombreCompleto || 'Psicólogo',
                rol: 'Psicólogo Clínico',
                iniciales: iniciales || 'PS',

                creadoEn: new Date(),
                actualizadoEn: new Date()
            };

            const resultado = await db.collection('foro_posts')
                .insertOne(nuevaPublicacion);

            res.status(201).json({
                mensaje: 'Publicación creada correctamente',
                post: {
                    ...nuevaPublicacion,
                    _id: resultado.insertedId
                }
            });
        } catch (error) {
            console.error('Error creando publicación:', error);
            res.status(500).json({
                error: 'No se pudo crear la publicación'
            });
        }
    }
);


// Editar una publicación propia.
app.put(
    '/api/posts/:id',
    verificarToken,
    verificarPsicologo,
    async (req, res) => {
        try {
            const { ObjectId } = require('mongodb');
            const { id } = req.params;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    error: 'Identificador de publicación no válido'
                });
            }

            const {
                titulo,
                provincia,
                fecha,
                imagen,
                descripcion
            } = req.body;

            const provinciasPermitidas = [
                'San José',
                'Alajuela',
                'Cartago',
                'Heredia',
                'Guanacaste',
                'Puntarenas',
                'Limón'
            ];

            if (
                typeof titulo !== 'string' ||
                !titulo.trim() ||
                titulo.trim().length > 150 ||
                typeof descripcion !== 'string' ||
                !descripcion.trim() ||
                descripcion.trim().length > 10000 ||
                typeof fecha !== 'string' ||
                !fecha.trim() ||
                !provinciasPermitidas.includes(provincia)
            ) {
                return res.status(400).json({
                    error: 'Los datos de la publicación no son válidos'
                });
            }

            const db = await conectarBD();

            const resultado = await db.collection('foro_posts')
                .updateOne(
                    {
                        _id: new ObjectId(id),
                        autorId: req.usuarioId
                    },
                    {
                        $set: {
                            titulo: titulo.trim(),
                            provincia,
                            fecha: fecha.trim(),
                            imagen: typeof imagen === 'string'
                                ? imagen.trim()
                                : '',
                            descripcion: descripcion.trim(),
                            actualizadoEn: new Date()
                        }
                    }
                );

            if (resultado.matchedCount === 0) {
                return res.status(404).json({
                    error: 'Publicación no encontrada o no te pertenece'
                });
            }

            res.json({
                mensaje: 'Publicación actualizada correctamente'
            });
        } catch (error) {
            console.error('Error editando publicación:', error);
            res.status(500).json({
                error: 'No se pudo editar la publicación'
            });
        }
    }
);


// Eliminar únicamente una publicación propia.
app.delete(
    '/api/posts/:id',
    verificarToken,
    verificarPsicologo,
    async (req, res) => {
        try {
            const { ObjectId } = require('mongodb');
            const { id } = req.params;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    error: 'Identificador de publicación no válido'
                });
            }

            const db = await conectarBD();

            const resultado = await db.collection('foro_posts')
                .deleteOne({
                    _id: new ObjectId(id),
                    autorId: req.usuarioId
                });

            if (resultado.deletedCount === 0) {
                return res.status(404).json({
                    error: 'Publicación no encontrada o no te pertenece'
                });
            }

            res.json({
                mensaje: 'Publicación eliminada correctamente'
            });
        } catch (error) {
            console.error('Error eliminando publicación:', error);
            res.status(500).json({
                error: 'No se pudo eliminar la publicación'
            });
        }
    }
);

//LO QUE NO SABES AFTON ES QUE YO SOY EL FAIV NAITS AT FREDDYS

async function iniciarServidor() {
  try {
    if (!process.env.JWT_SECRET) {
      throw new Error(
        'Falta configurar JWT_SECRET en el archivo .env'
      );
    }

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error(
        'Faltan EMAIL_USER o EMAIL_PASS en el archivo .env'
      );
    }

    await transporter.verify();
    console.log('Servicio de correo conectado correctamente');

    await conectarBD();

    app.listen(PORT, () => {
      console.log(
        `Servidor Amaeno corriendo en http://localhost:${PORT} conectado a MongoDB`
      );
    });
  } catch (error) {
    console.error('Error al iniciar el servidor:', error.message);
    process.exit(1);
  }
}

iniciarServidor();
