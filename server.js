// MCP backend
//
// This module needed NO functional changes for the API-key flow. It has no
// opinion about how the caller (mcp-app) got its token — OAuth code flow or
// API-key exchange both produce the exact same shape of RS256 JWT, bound to
// the same MCP_APP_RESOURCE_URL audience. This service keeps doing exactly
// what it did before: verify the token cryptographically and by audience,
// then forward to the customer backend's data API.
import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  console.log(`[MCP BACKEND REQ] ${req.method} ${req.url}`);
  next();
});

const CUSTOMER_BACKEND_URL = process.env.CUSTOMER_BACKEND_URL || "https://apikey-customer-backend.onrender.com";

// The resource identifier that tokens flowing through this service must be
// bound to. This is the same value mcp-app requests as `resource` when it
// calls the customer backend's /api/exchange-api-key endpoint, and the same
// value mcp-app checks against its own `${host}/mcp` — i.e. the MCP
// protected resource this token was actually issued for. Without this
// check, any token signed by the customer backend's key (for *any*
// purpose) would be accepted here.
const MCP_APP_RESOURCE_URL = process.env.MCP_APP_RESOURCE_URL || "https://apikey-mcp-app.onrender.com/mcp";

// Helper to convert JWK from Customer Backend into standard PEM format for JWT verification
let cachedPemPublicKey = null;

async function getPublicKeyFromJWKS() {
  if (cachedPemPublicKey) return cachedPemPublicKey;

  const resKey = await fetch(`${CUSTOMER_BACKEND_URL}/.well-known/jwks.json`);
  if (!resKey.ok) throw new Error(`Failed to fetch JWKS: ${resKey.status}`);

  const jwks = await resKey.json();
  const jwk = jwks.keys && jwks.keys[0];
  if (!jwk) throw new Error("No public key found in JWKS");

  const keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
  cachedPemPublicKey = keyObject.export({ type: "spki", format: "pem" });
  return cachedPemPublicKey;
}

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const publicKey = await getPublicKeyFromJWKS();

    const verifiedPayload = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
      audience: MCP_APP_RESOURCE_URL
    });

    req.user = verifiedPayload.sub;
    next();
  } catch (err) {
    console.error("[MCP BACKEND AUTH ERROR]", err.message);
    cachedPemPublicKey = null;
    return res.status(403).json({ error: "forbidden", message: "Token verification failed" });
  }
};

app.get("/api/v1/projects", authenticateToken, async (req, res) => {
  try {
    const response = await fetch(`${CUSTOMER_BACKEND_URL}/api/data`, {
      headers: { Authorization: req.headers.authorization }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: "failed_to_fetch_data" });
    }

    const data = await response.json();

    res.json({
      status: "success",
      user: req.user,
      data: data
    });
  } catch (err) {
    console.error("[MCP BACKEND ERROR]", err.message);
    res.status(500).json({ error: "internal_error" });
  }
});

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`MCP Backend Layer running on port ${port}`));