const express = require('express');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;
const saltRounds = 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many login attempts from this IP, please try again later.'
});

// Middleware
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from public directory
app.use(session({
    secret: 'your_secret_key', // Change this to a secure random string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set secure: true in production with HTTPS
}));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mySecureWebsiteDB').then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Define Post Schema and Model
const postSchema = new mongoose.Schema({
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    title: String,
    content: String,
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', postSchema);

// Middleware to check if the user is logged in
function checkAuthenticated(req, res, next) {
    if (req.session.user) {
        next(); // User is logged in, continue to requested route
    } else {
        res.redirect('/login'); // Redirect to login if not authenticated
    }
}

// Serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html')); 
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Dashboard route
app.get('/dashboard', checkAuthenticated, async (req, res) => {
    const username = req.session.user;
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="styles.css"> <!-- Link to your CSS -->
            <title>Dashboard</title>
        </head>
        <body>
            <h1>Welcome, ${username}!</h1>
            <p><a href="/my-posts">View Your Posts</a></p>
            <p><a href="/create-post">Create a new blog post</a></p>
            <form action="/logout" method="POST">
                <button type="submit">Logout</button>
            </form>
        </body>
        </html>
    `);
});

app.get('/create-post', checkAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'create-post.html'));
});

// Registration route
app.post('/register', [
    body('username')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long.')
        .isAlphanumeric().withMessage('Username must be alphanumeric.')
        .trim().escape(),
    body('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.')
        .trim().escape(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(400).send('User already exists!');
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ username, password: hashedPassword });

    try {
        await newUser.save();
        res.redirect('/dashboard');
    } catch (error) {
        res.status(500).send('Error registering user.');
    }
});

// Login route
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).send(renderErrorPage('Invalid User', 'The username you entered is invalid. Please register or try again.'));
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
        req.session.user = username;
        res.redirect('/dashboard');
    } else {
        res.status(401).send(renderErrorPage('Invalid Password', 'The password you entered is incorrect. Please try again.'));
    }
});

function renderErrorPage(title, message) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="styles.css">
            <title>${title}</title>
        </head>
        <body>
            <h1>${title}</h1>
            <p>${message}</p>
            <form action="/" method="GET">
                <button type="submit">Try Again</button>
            </form>
        </body>
        </html>
    `;
}

// Create Post Route
app.post('/create-post', checkAuthenticated, async (req, res) => {
    const { title, content } = req.body;
    const username = req.session.user;

    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).send('User not found.');
    }

    const newPost = new Post({
        title,
        content,
        author: user._id
    });

    try {
        await newPost.save();
        res.redirect('/dashboard');
    } catch (error) {
        res.status(500).send('Error creating post.');
    }
});

// Delete Post Route
app.post('/delete-post/:id', checkAuthenticated, async (req, res) => {
    const postId = req.params.id;
    const username = req.session.user;

    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).send('User not found.');
    }

    try {
        await Post.deleteOne({ _id: postId, author: user._id });
        res.redirect('/dashboard');
    } catch (error) {
        res.status(500).send('Error deleting post.');
    }
});

// API Route to get posts
app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find({}).populate('author', 'username');
        res.json(posts);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching posts' });
    }
});

// View User Posts Route
app.get('/my-posts', checkAuthenticated, async (req, res) => {
    const username = req.session.user;
    const user = await User.findOne({ username });
    const userPosts = await Post.find({ author: user._id });

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="styles.css">
            <title>Your Posts</title>
        </head>
        <body>
            <h1>Your Posts</h1>
            <ul>
                ${userPosts.map(post => `
                    <li>
                        <h3>${post.title}</h3>
                        <p>${post.content}</p>
                        <form action="/delete-post/${post._id}" method="POST">
                            <button type="submit">Delete Post</button>
                        </form>
                    </li>`).join('')}
            </ul>
            <p><a href="/create-post">Create a new blog post</a></p>
            <p><a href="/dashboard">Back to Dashboard</a></p>
        </body>
        </html>
    `);
});

// Display Posts Route (publicly accessible)
app.get('/posts', async (req, res) => {
    try {
        const posts = await Post.find({}).populate('author', 'username');
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel="stylesheet" href="styles.css">
                <title>All Posts</title>
            </head>
            <body>
                <h1>All Posts</h1>
                <ul>
                    ${posts.map(post => `
                        <li>
                            <h3>${post.title} by ${post.author.username}</h3>
                            <p>${post.content}</p>
                        </li>`).join('')}
                </ul>
                <a href="/">Back to Home</a>
            </body>
            </html>
        `);
    } catch (error) {
        res.status(500).send('Error retrieving posts');
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
