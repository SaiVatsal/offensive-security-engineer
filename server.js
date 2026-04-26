import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

const app = express();

// CRITICAL MIDDLEWARE: Parses incoming requests with JSON payloads.
app.use(express.json());

const SECRET_FLAG = process.env.SECRET_FLAG;

// Define the Database Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});

const User = mongoose.model('User', userSchema);

// In-memory token store for the lab session
let activeAdminToken = null;

// THE VULNERABLE LOGIN ENDPOINT:
app.post('/api/admin/login', async (req, res) => {
    try {
        const passwordInput = req.body.password;

        // --- THE NAIVE FIREWALL ---
        // The developer learned about NoSQL injections and tried to block the $ne operator.
        // However, they failed to block other logical operators.
        if (passwordInput && typeof passwordInput === 'object' && passwordInput.$ne !== undefined) {
            console.log("[FIREWALL] Blocked malicious $ne operator.");
            return res.status(403).json({ error: "Forbidden: Malicious payload detected." });
        }

        // The vulnerability: passing the raw request body directly into the database query.
        const user = await User.findOne({
            username: req.body.username,
            password: passwordInput
        });

        if (user) {
            if (user.role === 'admin') {
                // Generate a temporary session token
                activeAdminToken = "admin_auth_" + Math.random().toString(36).substring(2, 15);
                return res.status(200).json({
                    status: "Success",
                    message: "Administrative Access Granted.",
                    token: activeAdminToken
                });
            } else {
                return res.status(403).json({ error: "Access Denied. You are not an admin." });
            }
        } else {
            return res.status(401).json({ error: "Invalid username or password." });
        }
    } catch (error) {
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

// THE SECURE VAULT ENDPOINT:
app.get('/api/admin/vault', (req, res) => {
    const authHeader = req.headers.authorization;

    // Check if the user provided the correct Bearer token generated during login
    if (authHeader && authHeader === `Bearer ${activeAdminToken}`) {
        return res.status(200).json({
            status: "Success",
            message: "Vault unlocked.",
            flag: SECRET_FLAG
        });
    } else {
        return res.status(401).json({ error: "Unauthorized. Valid session token required." });
    }
});

// LAB INITIALIZATION LOGIC
async function initializeLab() {
    try {
        console.log("Booting up In-Memory MongoDB Server...");
        const mongoServer = await MongoMemoryServer.create({ binary: { version: '7.0.14' } });
        const mongoUri = mongoServer.getUri();

        await mongoose.connect(mongoUri);
        console.log("Connected to In-Memory MongoDB at:", mongoUri);

        await User.create({
            username: "admin",
            password: "super_secret_admin_password_" + Math.random().toString(36).substring(2, 15),
            role: "admin"
        });
        console.log("Admin user seeded successfully.");

        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Vulnerable API running on http://localhost:${PORT}`);
            console.log("Awaiting NoSQL Injection payloads...");
        });

    } catch (err) {
        console.error("Failed to initialize lab:", err);
        process.exit(1);
    }
}

initializeLab();