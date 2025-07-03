"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const express_session_1 = __importDefault(require("express-session"));
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const zod_1 = require("zod");
const crypto_1 = __importDefault(require("crypto"));
const TokenManager_1 = require("./TokenManager");
const GoogleSheetsService_1 = require("./GoogleSheetsService");
// Initialize services
const tokenManager = new TokenManager_1.TokenManager();
const sheetsService = new GoogleSheetsService_1.GoogleSheetsService(tokenManager);
// Create Express app with security middleware
const app = (0, express_1.default)();
// IMPORTANT: Trust proxy for Cloud Run
app.set('trust proxy', true);
app.use(express_1.default.json({ limit: '10mb' }));
app.use((0, helmet_1.default)({
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));
app.use((0, cors_1.default)({
    origin: [
        'https://claude.ai',
        'https://cursor.sh',
        'http://localhost:6274', // MCP Inspector
        'https://inspector.modelcontextprotocol.io', // Web-based MCP Inspector
        /^http:\/\/localhost:\d+$/ // Any localhost port for development
    ],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-MCP-Version',
        'mcp-session-id',
        'mcp-protocol-version', // Added for MCP Inspector
        'x-user-id'
    ]
}));
app.use((0, express_session_1.default)({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Only secure in production
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        sameSite: 'lax' // Important for OAuth flows
    },
    name: 'mcp-session', // Custom session name
    proxy: true // Important for Cloud Run
}));
// Rate limiting - Fixed for Cloud Run
const rateLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});
app.use(rateLimiter);
// Initialize MCP Server
const mcpServer = new mcp_js_1.McpServer({
    name: "google-sheets-mcp",
    version: "1.0.0"
});
// Store user sessions
const userSessions = {};
// Register MCP tools - FIXED: Removed 'name' property from options
mcpServer.registerTool("create-spreadsheet", {
    description: "Creates a new Google Spreadsheet with specified title",
    inputSchema: {
        title: zod_1.z.string().min(1).max(100).describe("Title for the new spreadsheet")
    }
}, async ({ title }, extra) => {
    // Get userId from sessionId mapping or use test user
    const userId = extra.sessionId ? userSessions[extra.sessionId] : 'test-user';
    if (!userId) {
        throw new Error('Authentication required');
    }
    // For testing purposes, return mock response if no real authentication
    if (userId === 'test-user' && !userSessions[extra.sessionId || '']) {
        return {
            content: [{
                    type: "text",
                    text: `[TEST MODE] Would create spreadsheet: ${title}\nNote: Complete OAuth flow first for real functionality.`
                }]
        };
    }
    const result = await sheetsService.createSpreadsheet(userId, title);
    return {
        content: [{
                type: "text",
                text: `Created spreadsheet: ${title}\nID: ${result.id}\nURL: ${result.url}`
            }]
    };
});
mcpServer.registerTool("read-sheet-data", {
    description: "Reads data from a specified range in a Google Sheet",
    inputSchema: {
        spreadsheetId: zod_1.z.string().describe("Google Spreadsheet ID"),
        range: zod_1.z.string().describe("Range to read (e.g., 'Sheet1!A1:C10')")
    }
}, async ({ spreadsheetId, range }, extra) => {
    const userId = extra.sessionId ? userSessions[extra.sessionId] : 'test-user';
    if (!userId) {
        throw new Error('Authentication required');
    }
    // For testing purposes, return mock response if no real authentication
    if (userId === 'test-user' && !userSessions[extra.sessionId || '']) {
        return {
            content: [{
                    type: "text",
                    text: `[TEST MODE] Would read data from ${spreadsheetId} range ${range}\nNote: Complete OAuth flow first for real functionality.`
                }]
        };
    }
    const data = await sheetsService.readData(userId, spreadsheetId, range);
    return {
        content: [{
                type: "text",
                text: `Data from ${range}:\n${JSON.stringify(data, null, 2)}`
            }]
    };
});
mcpServer.registerTool("write-sheet-data", {
    description: "Writes data to a specified range in a Google Sheet",
    inputSchema: {
        spreadsheetId: zod_1.z.string().describe("Google Spreadsheet ID"),
        range: zod_1.z.string().describe("Range to write to (e.g., 'Sheet1!A1:C10')"),
        values: zod_1.z.array(zod_1.z.array(zod_1.z.any())).describe("2D array of values to write")
    }
}, async ({ spreadsheetId, range, values }, extra) => {
    const userId = extra.sessionId ? userSessions[extra.sessionId] : 'test-user';
    if (!userId) {
        throw new Error('Authentication required');
    }
    // For testing purposes, return mock response if no real authentication
    if (userId === 'test-user' && !userSessions[extra.sessionId || '']) {
        return {
            content: [{
                    type: "text",
                    text: `[TEST MODE] Would write data to ${spreadsheetId} range ${range}\nData: ${JSON.stringify(values)}\nNote: Complete OAuth flow first for real functionality.`
                }]
        };
    }
    const updatedCells = await sheetsService.writeData(userId, spreadsheetId, range, values);
    return {
        content: [{
                type: "text",
                text: `Successfully wrote data to ${range}. Updated ${updatedCells} cells.`
            }]
    };
});
// Session management for MCP HTTP transport
const transports = {};
// MCP endpoint - FIXED: Using proper Express handler pattern
const mcpHandler = async (req, res) => {
    try {
        const sessionId = req.headers['mcp-session-id'];
        let transport;
        if (sessionId && transports[sessionId]) {
            transport = transports[sessionId];
        }
        else if (req.body?.method === 'initialize') {
            const newSessionId = crypto_1.default.randomUUID();
            transport = new streamableHttp_js_1.StreamableHTTPServerTransport({
                sessionIdGenerator: () => newSessionId,
                onsessioninitialized: (id) => {
                    transports[id] = transport;
                    // Map session to user if provided
                    const userId = req.headers['x-user-id'];
                    if (userId) {
                        userSessions[id] = userId;
                    }
                }
            });
            await mcpServer.connect(transport);
        }
        else {
            return res.status(400).json({ error: 'Invalid request or missing session' });
        }
        await transport.handleRequest(req, res, req.body);
    }
    catch (error) {
        console.error('MCP request error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
app.post('/mcp', mcpHandler);
// OAuth endpoints - FIXED: Using proper Express handler pattern
const authHandler = async (req, res) => {
    const state = crypto_1.default.randomBytes(32).toString('hex');
    const userId = req.query.user_id;
    if (!userId) {
        return res.status(400).json({ error: 'user_id parameter required' });
    }
    console.log('Setting session state:', state);
    req.session.state = state;
    req.session.userId = userId;
    // Force session save
    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
            return res.status(500).json({ error: 'Session save failed' });
        }
        console.log('Session saved successfully');
        const authUrl = sheetsService.getAuthUrl(state);
        res.redirect(authUrl);
    });
};
app.get('/auth', authHandler);
const oauthCallbackHandler = async (req, res) => {
    const { code, state } = req.query;
    console.log('OAuth callback received:');
    console.log('Query state:', state);
    console.log('Session state:', req.session.state);
    console.log('Session userId:', req.session.userId);
    console.log('Authorization code received:', code ? 'yes' : 'no');
    if (!state || !req.session.state || state !== req.session.state) {
        console.error('State mismatch:', {
            queryState: state,
            sessionState: req.session.state,
            sessionExists: !!req.session
        });
        return res.status(400).json({
            error: 'State mismatch',
            debug: {
                queryState: state,
                sessionState: req.session.state,
                sessionExists: !!req.session
            }
        });
    }
    if (!code || !req.session.userId) {
        console.error('Missing parameters:', { code: !!code, userId: !!req.session.userId });
        return res.status(400).json({ error: 'Missing required parameters' });
    }
    try {
        console.log('Attempting OAuth callback with userId:', req.session.userId);
        await sheetsService.handleOAuthCallback(req.session.userId, code);
        console.log('OAuth callback successful');
        res.json({ success: true, message: 'Successfully connected to Google Sheets' });
    }
    catch (error) {
        console.error('OAuth callback error:', error);
        console.error('Error details:', {
            message: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined
        });
        res.status(500).json({
            error: 'Authentication failed',
            debug: error instanceof Error ? error.message : 'Unknown error'
        });
    }
};
app.get('/oauth2callback', oauthCallbackHandler);
// OAuth metadata for Dynamic Client Registration - FIXED: Using proper Express handler pattern
app.get('/.well-known/oauth-authorization-server', (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/auth`,
        token_endpoint: `${baseUrl}/oauth2callback`,
        registration_endpoint: `${baseUrl}/oauth/register`,
        scopes_supported: ['read', 'write'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256']
    });
});
// OAuth protected resource metadata (for MCP Inspector compatibility)
app.get('/.well-known/oauth-protected-resource', (req, res) => {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
        resource: baseUrl,
        authorization_servers: [`${baseUrl}`],
        scopes_supported: ['read', 'write'],
        bearer_methods_supported: ['header', 'body', 'query'],
        resource_documentation: `${baseUrl}/docs`
    });
});
// Health check for Cloud Run - FIXED: Removed explicit type annotations
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0'
    });
});
// Debug endpoint to check environment variables
app.get('/debug', (req, res) => {
    res.json({
        env: {
            NODE_ENV: process.env.NODE_ENV || 'not set',
            GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ? 'set' : 'not set',
            GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || 'not set',
            SESSION_SECRET: process.env.SESSION_SECRET ? 'set' : 'not set',
            GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ? 'set' : 'not set',
            ENCRYPTION_KEY: process.env.ENCRYPTION_KEY ? 'set' : 'not set'
        }
    });
});
// Start server - Fix the PORT type issue
const PORT = parseInt(process.env.PORT || '8080', 10);
app.listen(PORT, '0.0.0.0', () => {
    console.log(`MCP Server for Google Sheets running on port ${PORT}`);
});
// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});
