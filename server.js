const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sharedsession = require('express-socket.io-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const validator = require('validator');
const axios = require('axios');
const cors = require('cors');

// Set up session middleware
const sessionMiddleware = session({
  store: new SQLiteStore({
    db: 'sessions.sqlite', // This is the file where sessions will be stored
    dir: './db', // Directory where the sessions.sqlite file will be placed
    // Other options can be set according to the connect-sqlite3 documentation
  }),
  secret: 'secret key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true, // Helps against XSS attacks
    maxAge: 24 * 60 * 60 * 1000 // 24 hours for example
  }
});
app.use(sessionMiddleware);

io.use(sharedsession(sessionMiddleware, {
  autoSave: true
}));

const corsOptions = {
  origin: 'http://localhost',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));

// Body parser middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON bodies

app.set('view engine', 'ejs');


// Initialize SQLite database
const db = new sqlite3.Database('./db/chatdb.sqlite', (err) => {
  if (err) {
    console.error(err.message);
  } else {
  console.log('Connected to the SQLite database.');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS banned_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reason TEXT,
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  }
});

function isAdmin(req, res, next) {
  console.log('Session:', req.session); // Add this line to log the session details
  if (req.session.user && req.session.user.role === 'admin') {
    return next();
  } else {
    return res.sendStatus(403);
  }
}

function isAuthenticated(req, res, next) {
  // This is a placeholder for whatever authentication check you have in place.
  // For example, you might check if the user's session indicates they are logged in:
  if (req.session.user) {
    return next(); // The user is authenticated, so continue to the next middleware
  } else {
    console.log('User is not authenticated, redirecting to /');// The user is not authenticated. Redirect them to the login page or send an error
    res.redirect('/'); // Redirect to the home page (or login page)
    // Alternatively, you could send a 401 Unauthorized status code:
    // res.sendStatus(401);
  }
}
app.get('/chat', isAuthenticated, (req, res) => {
  // At this point, the user is authenticated, so you can render the chat view
  if (req.session.user) { // Make sure the user object exists in the session
    res.render('chat', {
      // Pass the username to the view from the session's user object
      username: req.session.user.username
    });
  } else {
    // If for some reason the user object is not in the session, handle the error
    res.redirect('/'); // Redirect to the login page or an error page
  }
});

app.get('/', (req, res) => {
  res.render('index');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      res.status(500).send('Error registering user');
    } else {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err) => {
        if (err) {
          res.status(500).send('Username already taken');
        } else {
          res.redirect('/login'); // Redirect to login page after successful registration
        }
      });
    }
  });
});

// Login POST route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Attempting to log in user:', username); // Log the attempt to log in

  db.get('SELECT id, password, role FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Error during database query:', err);
      return res.status(500).send('Error logging in');
    }

    if (row) {
      bcrypt.compare(password, row.password, (err, result) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return res.status(500).send('Error during password comparison');
        }

        if (result) {
          req.session.user = { id: row.id, role: row.role, username: username };
          console.log('User authenticated, saving session:', req.session.user); // Log the authenticated user

          req.session.save(err => {
            if (err) {
              console.error('Error saving session:', err);
              return res.status(500).send('Error saving session');
            }

            console.log('Session saved, redirecting to /chat'); // Log the successful session save
            res.redirect('/chat'); // Redirect to chat page after successful login
          });
        } else {
          console.log('Invalid credentials for user:', username); // Log the invalid credentials
          res.status(401).send('Invalid credentials');
        }
      });
    } else {
      console.log('User not found:', username); // Log the user not found
      res.status(401).send('User not found');
    }
  });
});



// Admin routes
app.post('/ban-user', isAdmin, (req, res) => {
  const { userId, reason } = req.body;

  // Escape the reason for security
  const escapedReason = validator.escape(reason);

  // Insert into banned_users table
  db.run('INSERT INTO banned_users (user_id, reason) VALUES (?, ?)', [userId, escapedReason], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error banning user');
    } else {
      io.emit('banUser', { userId, reason: escapedReason });
      res.status(200).send('User banned');
    }
  });
});

app.post('/delete-message', isAdmin, (req, res) => {
  const { messageId } = req.body;

  // Delete the message from the messages table
  db.run('DELETE FROM messages WHERE id = ?', [messageId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error deleting message');
    } else {
      io.emit('deleteMessage', messageId);
      res.status(200).send('Message deleted');
    }
  });
});

io.on('connection', (socket) => {
  // Retrieve the userId from the socket's session
  const userId = socket.handshake.session.user ? socket.handshake.session.user.id : null;
  const userSockets = {};

  if (!userId) {
    console.error('User ID not found in session');
    return; // Stop further execution if userId is not found
  }
  
  let username;

  // Fetch the username from the database
  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error(err);
      return;
    }
    username = row ? row.username : null;
    console.log(`${username} connected`); // Log the username to the console

    // Broadcast to all sockets that a user has joined
    socket.broadcast.emit('userJoined', `${username} has joined the chat`);
  });

  // Fetch the last 10 messages from the database
  db.all('SELECT users.username, messages.message FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC LIMIT 10', (err, rows) => {
    if (err) {
      console.error(err);
      return;
    }
    socket.emit('chatHistory', rows.reverse());
  });

  // ... other code ...

  socket.on('chatMessage', (msg) => {
    const parts = msg.split(' ');
    const command = parts[0];
    const targetUsername = parts[1];
  
    // Helper function to check admin privileges
    const checkAdminPrivileges = (callback) => {
      db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        if (row && row.role === 'admin') {
          callback();
        } else {
          socket.emit('adminError', 'You do not have permission to perform this action.');
        }
      });
    };
  
    if (command === '/ban') {
      // Set the reason to the joined string of all parts after the command and username, or a default reason if not provided
      const reason = parts.length > 2 ? parts.slice(2).join(' ') : 'No reason provided';
      checkAdminPrivileges(() => {
        // Perform the ban operation
        db.run('INSERT INTO banned_users (user_id, reason) SELECT id, ? FROM users WHERE username = ?', [reason, targetUsername], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          if (this.changes > 0) {
            console.log(`User ${targetUsername} has been banned. Reason: ${reason}`);
            socket.broadcast.emit('userBanned', `User ${targetUsername} has been banned. Reason: ${reason}`);
          } else {
            socket.emit('banError', `User ${targetUsername} does not exist or is already banned.`);
          }
        });
      });
    } else if (command === '/unban' && parts.length >= 2) {
      checkAdminPrivileges(() => {
        // Perform the unban operation
        db.run('DELETE FROM banned_users WHERE user_id = (SELECT id FROM users WHERE username = ?)', [targetUsername], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          if (this.changes > 0) {
            console.log(`User ${targetUsername} has been unbanned.`);
            socket.emit('unbanSuccess', `User ${targetUsername} has been unbanned.`);
          } else {
            socket.emit('unbanError', `User ${targetUsername} does not exist or is not banned.`);
          }
        });
      });
    } else {
      // Normal chat message handling
      db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        if (!row) {
          console.error('User not found in database');
          socket.emit('errorMessage', 'User not found.');
          return;
        }
        const username = row.username;
    
        db.run('INSERT INTO messages (user_id, message) VALUES (?, ?)', [userId, msg], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          const insertedMessageId = this.lastID;
          io.emit('chatMessage', {
            username: username,
            message: msg,
            userId: userId, // Use the userId from the session
            messageId: insertedMessageId,
            timestamp: new Date()
          });
        });
      });
    }
  });
  
  socket.on('disconnect', () => {
    console.log(`${username} disconnected`); // Log the username to the console
  });
  
  
  socket.on('disconnect', () => {
    console.log(`${username} disconnected`); // Log the username to the console
  });
});


// Start the server
const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


