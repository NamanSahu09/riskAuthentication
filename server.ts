import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import axios from "axios";
import sslChecker from "ssl-checker";
import dns from "dns";
import net from "net";
import { promisify } from "util";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const lookupDns = promisify(dns.lookup);
const JWT_SECRET = "security-analysis-secret-key-2024";

// In-memory data structures (Note: Replaces DB for demo)
const users: any[] = [];
const histories: any[] = [];

export const app = express();
app.use(express.json());

// --- Auth Middleware ---
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return next();

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return next();
    req.user = user;
    next();
  });
};

app.use(authenticateToken);

// --- Auth Routes ---
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields are required" });

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ error: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), name, email, password: hashedPassword };
  users.push(newUser);

  const token = jwt.sign({ id: newUser.id, email: newUser.email, name: newUser.name }, JWT_SECRET);
  res.json({ token, user: { id: newUser.id, name: newUser.name, email: newUser.email } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET);
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.get("/api/auth/me", (req: any, res) => {
  if (!req.user) return res.status(401).json({ error: "Not authenticated" });
  res.json(req.user);
});

// --- Security Scanning Routes ---
app.post("/api/check-security", async (req: any, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  try {
    let targetUrl = url;
    if (!targetUrl.startsWith("http")) targetUrl = `https://${targetUrl}`;
    const domain = new URL(targetUrl).hostname;

    // 1. SSL/TLS Checks
    let sslInfo = null;
    try {
      sslInfo = await sslChecker(domain);
    } catch (e) {
      sslInfo = { valid: false, error: "SSL check failed" };
    }

    // 2. Header Checks
    let headersInfo: any = null;
    try {
      const response = await axios.get(targetUrl, { 
        timeout: 5000,
        maxRedirects: 5,
        validateStatus: () => true 
      });
      
      const headers = response.headers;
      headersInfo = {
        csp: headers["content-security-policy"] || null,
        xFrameOptions: headers["x-frame-options"] || null,
        xssProtection: headers["x-xss-protection"] || null,
        contentTypeOptions: headers["x-content-type-options"] || null,
        referrerPolicy: headers["referrer-policy"] || null,
        hsts: headers["strict-transport-security"] || null,
        server: headers["server"] || "Unknown",
        isHttps: targetUrl.startsWith("https")
      };
    } catch (e) {
      headersInfo = { error: "Failed to fetch headers", isHttps: targetUrl.startsWith("https") };
    }

    // 3. DNS Checks
    let dnsInfo = null;
    try {
      const addresses = await lookupDns(domain);
      dnsInfo = { ip: addresses.address };
    } catch (e) {
      dnsInfo = { error: "DNS lookup failed" };
    }

    // Construct final report
    const results = {
      id: Date.now().toString(),
      domain,
      timestamp: new Date().toISOString(),
      ssl: sslInfo,
      headers: headersInfo,
      dns: dnsInfo,
      checks: [
        { name: "SSL Certificate", status: sslInfo?.valid ? "pass" : "fail", detail: sslInfo?.valid ? `Valid until ${sslInfo.validTo}` : "Invalid or Missing" },
        { name: "HTTPS Support", status: targetUrl.startsWith("https") ? "pass" : "fail", detail: targetUrl.startsWith("https") ? "Securely using HTTPS" : "Site is using insecure HTTP" },
        { name: "HSTS Header", status: headersInfo?.hsts ? "pass" : "fail", detail: headersInfo?.hsts || "Missing" },
        { name: "CSP Header", status: headersInfo?.csp ? "pass" : "warning", detail: headersInfo?.csp ? "Header present" : "Vulnerable to XSS (Missing CSP)" },
        { name: "X-Frame-Options", status: headersInfo?.xFrameOptions ? "pass" : "warning", detail: headersInfo?.xFrameOptions ? "Clickjacking protection present" : "Missing" },
      ],
      score: calculateScore(sslInfo, headersInfo)
    };

    if (req.user) {
      histories.push({ ...results, userId: req.user.id });
    }

    res.json(results);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/history", (req: any, res) => {
  if (!req.user) return res.json([]);
  const userHistory = histories.filter(h => h.userId === req.user.id);
  res.json(userHistory);
});

function calculateScore(ssl: any, headers: any) {
  let score = 50; 
  if (ssl?.valid) score += 20;
  if (headers?.isHttps) score += 10;
  if (headers?.hsts) score += 5;
  if (headers?.csp) score += 5;
  if (headers?.xFrameOptions) score += 5;
  if (headers?.xssProtection) score += 5;
  return Math.min(score, 100);
}

async function startServer() {
  const PORT = 3000;

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  if (!process.env.VERCEL) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  }
}

startServer();
