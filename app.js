const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const app = express();
const PORT = 4000;

// Middleware
app.use(cors());
app.use(express.json());

// Conexión a MySQL
let connection;
(async () => {
    try {
        connection = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'admin',
            database: 'Login'
        });
        console.log('Conectado a la base de datos MySQL');
    } catch (error) {
        console.error('Error de conexión a la base de datos:', error);
    }
})();

// Ruta para registrar usuario
app.post('/register', async (req, res) => {
    const { usuario, clave } = req.body;

    if (!usuario || !clave) {
        return res.status(400).send('Usuario y clave son obligatorios');
    }

    try {
        // Validar si el usuario ya existe
        const [rows] = await connection.execute('SELECT * FROM usuarios WHERE usuario = ?',
            [usuario]);
        if (rows.length > 0) {
            return res.status(409).send('El usuario ya existe');
        }

        // Encriptar la clave
        const hash = await bcrypt.hash(clave, 10);

        // Insertar nuevo usuario
        await connection.execute('INSERT INTO usuarios (usuario, clave) VALUES (?, ?)', [usuario, hash]);
        res.status(200).send('Usuario registrado correctamente');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el servidor');
    }
});

// Ruta para login
app.post('/login', async (req, res) => {
    const { usuario, clave } = req.body;

    if (!usuario || !clave) {
        return res.status(400).send('Faltan datos');
    }

    try {
        // Buscar usuario por nombre
        const [results] = await connection.query(
            "SELECT * FROM usuarios WHERE usuario = ?",
            [usuario]
        );

        if (results.length > 0) {
            const match = await bcrypt.compare(clave, results[0].clave);

            if (match) {
                res.status(200).send('Inicio de sesión exitoso');
            } else {
                res.status(401).send('Clave incorrecta');
            }
        } else {
            res.status(401).send('Usuario no encontrado');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Error del servidor');
    }
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
