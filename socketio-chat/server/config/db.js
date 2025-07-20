const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Render-compatible connection logic
    const mongoURI = process.env.MONGODB_URI || process.env.MONGO_URI;
    
    if (!mongoURI) {
      throw new Error('MongoDB URI not configured in environment variables');
    }

    console.log('\n🔌 Attempting to connect to MongoDB...');
    console.log('⏳ Please wait...\n');
    
    await mongoose.connect(mongoURI);  // Removed deprecated options
    
    console.log('┌──────────────────────────────────────────────┐');
    console.log('│ ✅  SUCCESS: Connected to MongoDB            │');
    console.log(`│ 🔗  Using: ${mongoURI.includes('localhost') ? 'Local DB' : 'Production DB'.padEnd(28)}│`);
    console.log('└──────────────────────────────────────────────┘\n');
  } catch (error) {
    console.log('\n┌──────────────────────────────────────────────┐');
    console.log('│ ❌  MONGODB CONNECTION ERROR                 │');
    console.log('├──────────────────────────────────────────────┤');
    console.log(`│ ${error.message.padEnd(44)}│`);
    console.log('└──────────────────────────────────────────────┘\n');
    process.exit(1);
  }
};

module.exports = connectDB;

//