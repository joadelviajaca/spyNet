import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

// --- CONFIGURACIÓN ---
const app = express();
const PORT = 3001; // Diferente al 3000 de React
const SECRET_KEY = 'top_secret_spy_key_123'; // En producción esto va en .env

app.use(cors());
app.use(express.json());

// --- BASE DE DATOS (EN MEMORIA) ---
let mongoServer;

const connectDB = async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
  console.log("💾 Base de datos en memoria conectada.");
  await seedDatabase();
};

// --- MODELOS ---
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['admin', 'agent'], default: 'agent' }
});

const MissionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  difficulty: { type: String, enum: ['Baja', 'Media', 'Alta', 'Imposible'] },
  status: { type: String, default: 'Pendiente' },
  agentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false } // Opcional
});

const User = mongoose.model('User', UserSchema);
const Mission = mongoose.model('Mission', MissionSchema);

// --- SEED (DATOS INICIALES) ---
const seedDatabase = async () => {
  const count = await User.countDocuments();
  if (count === 0) {
    const hashedPassword = await bcrypt.hash('1234', 10);
    
    // 1. Crear el Jefe (Admin)
    await User.create({
      email: 'm@mi6.com',
      password: hashedPassword,
      name: 'M (Handler)',
      role: 'admin'
    });

    // 2. Crear a 007 (Agent)
    await User.create({
      email: 'bond@mi6.com',
      password: hashedPassword,
      name: 'James Bond',
      role: 'agent'
    });

    // 3. Crear Misiones
    await Mission.create([
      { title: 'Operación Skyfall', description: 'Recuperar el disco duro en Estambul.', difficulty: 'Alta' },
      { title: 'Casino Royale', description: 'Infiltrarse en partida de póker de alto riesgo.', difficulty: 'Imposible' },
      { title: 'Recogida de Paquete', description: 'Recoger traje de la tintorería.', difficulty: 'Baja' }
    ]);

    console.log("🌱 Datos sembrados: Usuarios (bond@mi6.com / 1234) y Misiones creadas.");
  }
};

// --- MIDDLEWARES ---
// Simula retardo de red para ver los spinners en React
app.use((req, res, next) => {
  setTimeout(next, 500); 
});

// Verifica el Token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) return res.status(401).json({ message: 'Acceso denegado. Se requiere Token.' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido o expirado.' });
    req.user = user;
    next();
  });
};

// --- RUTAS DE AUTENTICACIÓN ---

// POST /auth/login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: 'Credenciales incorrectas (Intenta: bond@mi6.com / 1234)' });
  }

  // Generamos Token
  const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, SECRET_KEY, { expiresIn: '1h' });
  
  res.json({ 
    token, 
    user: { email: user.email, name: user.name, role: user.role } 
  });
});

// --- RUTAS DE MISIONES (PROTEGIDAS) ---

// GET /missions - Solo usuarios autenticados
app.get('/missions', authenticateToken, async (req, res) => {
  const missions = await Mission.find();
  res.json(missions);
});

// POST /missions - Solo ADMINS pueden crear misiones
app.post('/missions', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Permisos insuficientes. Solo "M" puede crear misiones.' });
  }
  
  try {
    const newMission = await Mission.create(req.body);
    res.status(201).json(newMission);
  } catch (error) {
    res.status(400).json({ message: 'Error creando misión' });
  }
});

// --- INICIAR SERVIDOR ---
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 SpyNet Server corriendo en http://localhost:${PORT}`);
  });
});