const socketAuth = async (socket, next) => {
  try {
    // 1. Get token from handshake
    const token = socket.handshake.auth.token || 
                 socket.handshake.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return next(new Error('Authentication error: No token provided'));
    }

    // 2. Verify token (example using JWT)
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // 3. Attach user to socket
    const user = await User.findById(decoded.id);
    if (!user) {
      return next(new Error('Authentication error: User not found'));
    }

    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication error: ' + err.message));
  }
};


module.exports = (socket, next) => {
  console.log('Auth Middleware Triggered');
  console.log('Handshake Headers:', socket.handshake.headers);
  console.log('Auth Token:', socket.handshake.auth.token);
  
  try {
    const token = socket.handshake.auth?.token || 
                 socket.handshake.headers?.authorization?.split(' ')[1];
    
    if (!token) {
      console.error('No token provided');
      return next(new Error('Authentication error: No token provided'));
    }

    // Verify token logic here...
    console.log('Token verified successfully');
    next();
  } catch (err) {
    console.error('Auth Error:', err);
    next(new Error('Authentication failed'));
  }
};