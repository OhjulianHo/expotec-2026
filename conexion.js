require('dotenv').config();
const { MongoClient } = require('mongodb');

const uri = process.env.MONGODB_URI; 
const client = new MongoClient(process.env.MONGODB_URI);

async function conectarBD() {
  try {
    // Conectamos al servidor de MongoDB
    await client.connect();
    
    // Opcional: Seleccionamos la base de datos específica
    const db = client.db(process.env.MONGO_DB_NAME);
    
    console.log('Conexión exitosa a MongoDB');
    return db; // Retornamos la instancia de la base de datos para usarla en el proyecto
  } catch (error) {
    console.error('Error al conectar con la base de datos de MongoDB:', error.message);
    throw error;
  }
}

module.exports = conectarBD;