const bcrypt = require('bcryptjs');

// Function to hash password
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Run this directly to generate a hash for your admin password
if (require.main === module) {
  const password = process.argv[2];
  if (!password) {
    console.error('Usage: node utils/hashPassword.js <password>');
    process.exit(1);
  }
  
  hashPassword(password).then(console.log);
}

module.exports = hashPassword;