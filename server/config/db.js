const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
     console.log();
     console.log('✅ Success!! Connected to MongoDB Compass');
  } catch (error) {
    console.log();
    console.error(`❌ Sorry!! MongoDB connection Error: ${error.message}`);
    console.log();
    process.exit(1);
  }
};

module.exports = connectDB;