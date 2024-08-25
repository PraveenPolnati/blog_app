const express = require('express');
const mysql = require('mysql2');
const bodyparser = require('body-parser');
const cors = require('cors'); // Import cors
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();
const jwtSecret = process.env.JWT_SECRET;

const app = express();
const port = 3002;

app.use(cors()); // Enable CORS
app.use(bodyparser.json());

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Praveen@822',
    database: 'blog_app'
});

connection.connect(err => {
    if (err) {
        console.log(err);
        process.exit(1);
    }
    console.log('database connected');
});

app.listen(port, () => {
    console.log('server started at', port);
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send(err);
        connection.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) return res.status(500).send(err);
            res.status(201).send('User registered');
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(401).send('User not found');

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send(err);
            if (!isMatch) return res.status(401).send('Invalid password');

            const token = jwt.sign({ id: user.id }, jwtSecret);
            res.json({ token });
        });
    });
});

const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.get('/posts', authenticateJWT, (req, res) => {
    connection.query(`SELECT id,
  title,
  content,
  author,
  DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS formatted_created_at FROM posts`, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.get('/posts/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    connection.query('SELECT * FROM posts WHERE id = ?', [id], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.json(results[0]);
    });
});

app.post('/posts', authenticateJWT, (req, res) => {
    const { title, content, author } = req.body;
    connection.query('INSERT INTO posts (title, content, author) VALUES (?, ?, ?)', [title, content, author], (err, results) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.status(201).json({ id: results.insertId });
    });
});

app.put('/posts/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { title, content, author } = req.body;
    connection.query('UPDATE posts SET title = ?, content = ?, author = ? WHERE id = ?', [title, content, author, id], (err) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.sendStatus(204);
    });
});

app.delete('/posts/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    connection.query('DELETE FROM posts WHERE id = ?', [id], (err) => {
        if (err) {
            res.status(500).send(err);
            return;
        }
        res.sendStatus(204);
    });
});
