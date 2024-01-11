const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const sharedsession = require('express-socket.io-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const validator = require('validator');
const axios = require('axios');
const cors = require('cors');

// Set up session middleware
const sessionMiddleware = session({
  secret: 'secret key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // for development, set to true in production with HTTPS
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

// Body parser middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON bodies
app.use(cors(corsOptions));
app.set('view engine', 'ejs');


// Initialize SQLite database
const db = new sqlite3.Database('./db/chatdb.sqlite', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQLite database.');  
});

function isAdmin(req, res, next) {
  const laravelSessionCookie = req.headers.cookie;

  axios.get('/api/user', {
    headers: {
      'Cookie': laravelSessionCookie
    }
  }).then(response => {
    if (response.data.role === 'admin') {
      return next();
    } else {
    return res.sendStatus(403);
  }
  }).catch(err => {
    return res.sendStatus(401);
  });
}

app.get('/', (req, res) => {
  res.render('index');
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
  const userId = socket.handshake.session.userId;
  const userSockets = {};
  
  let name;

  // Fetch the username from the database
  db.get('SELECT name FROM users WHERE id = ?', [userId], (err, row) => {
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
        const username = row.username;
        db.run('INSERT INTO messages (user_id, message) VALUES (?, ?)', [userId, msg], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          io.emit('chatMessage', { username, message: msg, timestamp: new Date() });
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


