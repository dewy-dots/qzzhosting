// server.js (Admin Panel funkciókkal)

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt'); // Jelszó titkosítás
const session = require('express-session'); // Session kezelés
const app = express();
const PORT = 8080; 
const saltRounds = 10;

let db; 

// --- ADMIN BEÁLLÍTÁSOK ---
const ADMIN_EMAIL = 'dewbyuisness609@gmail.com';
const ADMIN_PASSWORD_PLAINTEXT = 'bedwars112233_'; // CSAK egyszer használjuk a hasheléshez!
let ADMIN_PASSWORD_HASH = ''; // Ebbe tároljuk a titkosított jelszót

// Middleware beállítások
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); 

// Session beállítások
app.use(session({
    secret: 'your_super_secret_key_qzz', // Ezt cseréld le egy egyedi, hosszú stringre!
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 napos session
}));

// Auth ellenőrző middleware
function requireAdmin(req, res, next) {
    if (req.session.isAdmin) {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

// Fenntartott nevek
const RESERVED_DOMAINS = ['www', 'dashpanel', 'admin', 'root', 'support', 'api', 'localhost'];

// ----------------------------------------------------
// ADATBÁZIS ÉS JELSZÓ HASHELÉS
// ----------------------------------------------------

async function initializeDB() {
    db = await sqlite.open({ filename: './mydomain.db', driver: sqlite3.Database });
    
    // Tábla létrehozása/frissítése
    await db.exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        redirect_url TEXT DEFAULT NULL
    );`);
    try { await db.exec(`ALTER TABLE users ADD COLUMN redirect_url TEXT DEFAULT NULL;`); } catch (e) { /* OK */ }

    // Jelszó hashelése indításkor (csak egyszer!)
    ADMIN_PASSWORD_HASH = await bcrypt.hash(ADMIN_PASSWORD_PLAINTEXT, saltRounds);
    console.log("Admin jelszó titkosítva.");

    console.log("Adatbázis inicializálva és kész!");
}

initializeDB().then(() => {

    // --- ADMIN ÚTVONALAK ---

    // Admin bejelentkező oldal
    app.get('/admin/login', (req, res) => {
        res.render('admin_login', { title: 'Admin Bejelentkezés' });
    });

    // Admin bejelentkezés POST
    app.post('/admin/login', async (req, res) => {
        const { email, password } = req.body;

        if (email === ADMIN_EMAIL) {
            const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

            if (match) {
                req.session.isAdmin = true;
                return res.redirect('/admin');
            }
        }
        res.send("Hibás email cím vagy jelszó.");
    });

    // Admin Dashboard (védett)
    app.get('/admin', requireAdmin, async (req, res) => {
        const domains = await db.all("SELECT * FROM users ORDER BY id DESC");
        res.render('admin_dashboard', { 
            title: 'Admin Panel', 
            domains: domains 
        });
    });

    // Domain törlése POST (védett)
    app.post('/admin/delete', requireAdmin, async (req, res) => {
        const { id } = req.body;
        try {
            await db.run("DELETE FROM users WHERE id = ?", id);
            res.redirect('/admin');
        } catch (error) {
            console.error('Törlési hiba:', error);
            res.status(500).send("Hiba történt a domain törlésekor.");
        }
    });

    // Admin kijelentkezés
    app.get('/admin/logout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/admin/login');
        });
    });
    
    // --- FELHASZNÁLÓI ÉS REGISZTRÁCIÓS ÚTVONALAK (változatlan) ---

    // Dashboard Útvonal (dashpanel.qzz.io)
    app.get('/', async (req, res, next) => {
        const host = req.get('host');
        if (host === 'dashpanel.qzz.io' || host === `localhost:${PORT}`) {
            const domains = await db.all("SELECT * FROM users"); 
            return res.render('index', { title: 'QZZ Domains - Dashboard', domains: domains });
        }
        next();
    });

    // Domain Regisztráció POST
    app.post('/order-domain', async (req, res) => {
        const { username, email } = req.body;
        if (!/^[a-z0-9]+$/.test(username) || username.length < 3) {
             return res.send("Hibás aldomain név.");
        }
        const existingUser = await db.get("SELECT username FROM users WHERE username = ?", username);
        if (existingUser || RESERVED_DOMAINS.includes(username)) {
            return res.send(`A(z) **${username}.qzz.io** már foglalt!`);
        }
        try {
            await db.run("INSERT INTO users (username, email) VALUES (?, ?)", username, email);
            res.send(`Sikeres regisztráció! Domain: **${username}.qzz.io**. 
                      <br><a href="http://${username}.qzz.io">Oldal</a> | 
                      <a href="http://dashpanel.qzz.io">Dashboard</a>`);
        } catch (error) { res.status(500).send("Hiba történt a regisztráció során."); }
    });

    // Átirányítás Beállítása POST
    app.post('/set-redirect', async (req, res) => {
        const { username, redirect_url } = req.body;
        let validUrl = redirect_url.trim();
        if (validUrl && !validUrl.startsWith('http')) { validUrl = 'http://' + validUrl; }
        try {
            await db.run("UPDATE users SET redirect_url = ? WHERE username = ?", validUrl || null, username);
            res.redirect('http://dashpanel.qzz.io');
        } catch (error) { res.status(500).send("Hiba történt az átirányítás frissítésekor."); }
    });


    // VADKÁRTYÁS ALDOMAIN LOGIKA (Változatlan, lásd az előző válasz)
    app.get('*', async (req, res) => {
        const fullHost = req.get('host'); 
        const parts = fullHost.split('.');
        const username = parts[0]; 
        
        if (username === 'dashpanel') {
            return res.status(404).send(`A kért **${fullHost}** cím nem támogatott formátumú.`);
        }
        const user = await db.get("SELECT username, redirect_url FROM users WHERE username = ?", username);

        if (user) {
            if (user.redirect_url) {
                return res.redirect(302, user.redirect_url);
            }
            return res.render('user_page', {
                username: user.username,
                fullHost: fullHost,
                title: `${user.username} - QZZ Oldala`
            });
        }
        res.status(404).send(`A kért **${fullHost}** aldomain nem létezik vagy nem lett regisztrálva.`);
    });


    // SZERVER INDÍTÁSA
    app.listen(PORT, () => {
        console.log(`Weboldal Kiszolgáló elindult a http://localhost:${PORT} címen.`);
        console.log(`Admin Bejelentkezés: http://dashpanel.qzz.io/admin/login`);
    });
    
}).catch(err => {
    console.error("Hiba az indításkor:", err);
});