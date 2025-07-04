import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { google } from 'googleapis';
import { z } from 'zod';
import crypto from 'crypto';
import { TokenManager } from './TokenManager';
import { GoogleSheetsService } from './GoogleSheetsService';

interface ClientRegistration {
  client_id: string;
  client_secret: string;
  client_id_issued_at: number;
  client_secret_expires_at: number;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  client_name: string;
  scope: string;
}

// Store user sessions
const userSessions: Record<string, string> = {};

const registeredClients = new Map<string, ClientRegistration>();
// Storage for authorization codes (temporary, expire after 10 minutes)
const authCodes = new Map<string, {
  client_id: string;
  code_challenge: string;
  expires_at: number;
  google_code: string;
  created_at: number;
}>();

// Storage for access tokens (expire after 1 hour)
const accessTokens = new Map<string, {
  client_id: string;
  scope: string;
  expires_at: number;
  refresh_token: string;
  created_at: number;
}>();

const sessionAuthHeaders = new Map<string, string>();

const clientGoogleTokens = new Map<string, {
  access_token: string;
  refresh_token?: string;
  expiry_date: number;
  scope: string[];
}>();

// Initialize services
const tokenManager = new TokenManager();
const sheetsService = new GoogleSheetsService(tokenManager);

// Create Express app with security middleware
const app = express();

// IMPORTANT: Trust proxy for Cloud Run
app.set('trust proxy', true);

app.use(express.urlencoded({ extended: true }));

app.use(express.json({ limit: '10mb' }));
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use(cors({
  origin: [
    'https://claude.ai',
    'https://*.claude.ai', // Allow subdomains
    'http://localhost:6274',
    'https://inspector.modelcontextprotocol.io',
    /^http:\/\/localhost:\d+$/
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-MCP-Version', 
    'mcp-session-id',
    'mcp-protocol-version',
    'x-user-id'
  ],
  exposedHeaders: ['WWW-Authenticate'] // Add this
}));

app.use(session({
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

const rateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500, // Higher limit for OAuth flows
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const userAgent = req.headers['user-agent'] || '';
    const path = req.path;
    
    const isClaudeAI = userAgent.toLowerCase().includes('claude') || 
                      userAgent.includes('python-httpx');
    const isOAuthPath = path.startsWith('/.well-known/') || 
                       path.startsWith('/oauth/') || 
                       path === '/mcp';
    
    if (isClaudeAI || isOAuthPath) {
      return true; // Skip rate limiting
    }
    
    return false;
  }
});

app.use(rateLimiter);

// Initialize MCP Server
const mcpServer = new McpServer({
  name: "google-sheets-mcp",
  version: "1.0.0"
});


// Add this helper function to validate Bearer tokens (add after your storage maps)
function validateBearerTokenBySession(sessionId: string | undefined): { valid: boolean; clientId?: string; userId?: string } {
  if (!sessionId) {
    console.log('No session ID provided');
    return { valid: false };
  }

  const authHeader = sessionAuthHeaders.get(sessionId);
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('Missing or invalid Authorization header for session:', sessionId);
    return { valid: false };
  }

  const token = authHeader.substring(7); // Remove "Bearer " prefix
  console.log('Validating token for session:', sessionId, 'token:', token);
  
  const tokenData = accessTokens.get(token);
  if (!tokenData) {
    console.log('Token not found in storage');
    console.log('Available tokens:', Array.from(accessTokens.keys()));
    return { valid: false };
  }

  // Check if token has expired
  if (tokenData.expires_at < Date.now()) {
    console.log('Token has expired');
    accessTokens.delete(token); // Clean up expired token
    sessionAuthHeaders.delete(sessionId); // Clean up session auth
    return { valid: false };
  }

  console.log('Token validated successfully for client:', tokenData.client_id);
  return { 
    valid: true, 
    clientId: tokenData.client_id,
    userId: `oauth_${tokenData.client_id}` // Generate a consistent user ID
  };
}

// Updated MCP tools using session-based authentication
// Replace your existing tool registrations with these:

// Helper function to get Google Sheets service for a client
async function getGoogleSheetsForClient(clientId: string): Promise<any> {
  const googleTokens = clientGoogleTokens.get(clientId);
  if (!googleTokens) {
    throw new Error('No Google tokens found for this client. Please complete OAuth flow.');
  }

  // Check if Google tokens are expired
  if (googleTokens.expiry_date <= Date.now()) {
    throw new Error('Google tokens have expired. Please re-authenticate.');
  }

  // Create a temporary user ID for the sheets service
  const tempUserId = `client_${clientId}`;
  
  // Store tokens temporarily so GoogleSheetsService can use them
  await tokenManager.storeTokens(tempUserId, googleTokens);
  
  // Create GoogleSheetsService instance - it will use tokenManager to get tokens
  return { tempUserId, sheetsService };
}

// Updated MCP tools with real Google Sheets API calls
// Simplified MCP tools that don't need to check auth (it's handled at HTTP level)
mcpServer.registerTool(
  "create-spreadsheet",
  {
    description: "Creates a new Google Spreadsheet with specified title",
    inputSchema: {
      title: z.string().min(1).max(100).describe("Title for the new spreadsheet")
    }
  },
  async ({ title }, extra) => {
    console.log('=== Create Spreadsheet Tool Called ===');
    console.log('Session ID:', extra.sessionId);
    
    // Authentication is already validated at the HTTP level, so we can proceed
    const tokenValidation = validateBearerTokenBySession(extra.sessionId);
    const clientId = tokenValidation.clientId!;
    console.log('Authenticated client:', clientId);
    
    try {
      console.log('Creating real spreadsheet with title:', title);
      
      // Get Google Sheets service for this client
      const { tempUserId } = await getGoogleSheetsForClient(clientId);
      
      // Create real spreadsheet using GoogleSheetsService
      const result = await sheetsService.createSpreadsheet(tempUserId, title);
      
      console.log('Spreadsheet created successfully:', result);
      
      return {
        content: [{
          type: "text",
          text: `✅ Spreadsheet created successfully!\n\nTitle: ${title}\nID: ${result.id}\nURL: ${result.url}`
        }]
      };
      
    } catch (error) {
      console.error('Error creating spreadsheet:', error);
      throw new Error(`Failed to create spreadsheet: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
);

mcpServer.registerTool(
  "read-sheet-data",
  {
    description: "Reads data from a specified range in a Google Sheet",
    inputSchema: {
      spreadsheetId: z.string().describe("Google Spreadsheet ID"),
      range: z.string().describe("Range to read (e.g., 'Sheet1!A1:C10')")
    }
  },
  async ({ spreadsheetId, range }, extra) => {
    console.log('=== Read Sheet Data Tool Called ===');
    console.log('Session ID:', extra.sessionId);
    
    // Authentication is already validated at the HTTP level
    const tokenValidation = validateBearerTokenBySession(extra.sessionId);
    const clientId = tokenValidation.clientId!;
    console.log('Authenticated client:', clientId);
    
    try {
      console.log('Reading real data from spreadsheet:', spreadsheetId, 'range:', range);
      
      // Get Google Sheets service for this client
      const { tempUserId } = await getGoogleSheetsForClient(clientId);
      
      // Read real data using GoogleSheetsService
      const data = await sheetsService.readData(tempUserId, spreadsheetId, range);
      
      console.log('Data read successfully, rows:', data.length);
      
      // Format the data nicely
      let formattedData = '';
      if (data.length === 0) {
        formattedData = 'No data found in the specified range.';
      } else {
        formattedData = data.map(row => row.join('\t')).join('\n');
      }
      
      return {
        content: [{
          type: "text",
          text: `✅ Data read from ${spreadsheetId} range ${range}:\n\n${formattedData}\n\nRows returned: ${data.length}`
        }]
      };
      
    } catch (error) {
      console.error('Error reading sheet data:', error);
      throw new Error(`Failed to read sheet data: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
);

mcpServer.registerTool(
  "write-sheet-data",
  {
    description: "Writes data to a specified range in a Google Sheet",
    inputSchema: {
      spreadsheetId: z.string().describe("Google Spreadsheet ID"),
      range: z.string().describe("Range to write to (e.g., 'Sheet1!A1:C10')"),
      values: z.array(z.array(z.any())).describe("2D array of values to write")
    }
  },
  async ({ spreadsheetId, range, values }, extra) => {
    console.log('=== Write Sheet Data Tool Called ===');
    console.log('Session ID:', extra.sessionId);
    
    // Authentication is already validated at the HTTP level
    const tokenValidation = validateBearerTokenBySession(extra.sessionId);
    const clientId = tokenValidation.clientId!;
    console.log('Authenticated client:', clientId);
    
    try {
      console.log('Writing real data to spreadsheet:', spreadsheetId, 'range:', range);
      console.log('Data to write:', JSON.stringify(values, null, 2));
      
      // Get Google Sheets service for this client
      const { tempUserId } = await getGoogleSheetsForClient(clientId);
      
      // Write real data using GoogleSheetsService
      const updatedCells = await sheetsService.writeData(tempUserId, spreadsheetId, range, values);
      
      console.log('Data written successfully, cells updated:', updatedCells);
      
      return {
        content: [{
          type: "text",
          text: `✅ Successfully wrote data to ${spreadsheetId} range ${range}.\n\nCells updated: ${updatedCells}\n\nData written:\n${values.map(row => row.join('\t')).join('\n')}`
        }]
      };
      
    } catch (error) {
      console.error('Error writing sheet data:', error);
      throw new Error(`Failed to write sheet data: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
);

// Session management for MCP HTTP transport
const transports: Record<string, StreamableHTTPServerTransport> = {};


const mcpHandler = async (req: any, res: any) => {
  try {
    const sessionId = req.headers['mcp-session-id'] as string;
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    const userAgent = req.headers['user-agent'] || '';
    const acceptHeader = req.headers['accept'] || '';
    
    console.log('=== MCP Request ===');
    console.log('Session ID:', sessionId);
    console.log('Authorization header:', authHeader ? 'present' : 'missing');
    console.log('User-Agent:', userAgent);
    console.log('Request method:', req.body?.method);
    
    const isClaudeAI = userAgent.toLowerCase().includes('claude') || 
                      req.headers['origin'] === 'https://claude.ai' ||
                      req.headers['referer']?.includes('claude.ai');
    
    // Fix Accept header for Claude.ai
    if (isClaudeAI && (!acceptHeader || !acceptHeader.includes('text/event-stream'))) {
      req.headers['accept'] = 'application/json, text/event-stream';
    }
    
    // CRITICAL CHANGE: For Claude.ai, require auth for EVERYTHING
    if (isClaudeAI && !authHeader) {
      console.log(`Claude.ai ${req.body?.method} request without auth - returning 401`);
      
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      
      return res.status(401)
         .set({
           'WWW-Authenticate': `Bearer realm="${baseUrl}"`,
           'Content-Type': 'application/json',
           'Access-Control-Allow-Origin': 'https://claude.ai',
           'Access-Control-Allow-Headers': 'Authorization, Content-Type, mcp-session-id, Accept',
           'Access-Control-Allow-Credentials': 'true'
         })
         .json({
           jsonrpc: "2.0",
           error: {
             code: -32000,
             message: 'Authentication required',
             data: {
               type: 'oauth_required',
               auth_url: `${baseUrl}/.well-known/oauth-authorization-server`
             }
           },
           id: req.body?.id || null
         });
    }
    
    // Validate Bearer token if present
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const tokenData = accessTokens.get(token);
      
      if (!tokenData || tokenData.expires_at < Date.now()) {
        console.log('Invalid or expired token');
        
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        
        return res.status(401)
           .set({
             'WWW-Authenticate': `Bearer realm="${baseUrl}"`,
             'Content-Type': 'application/json',
             'Access-Control-Allow-Origin': 'https://claude.ai',
             'Access-Control-Allow-Headers': 'Authorization, Content-Type, mcp-session-id, Accept',
             'Access-Control-Allow-Credentials': 'true'
           })
           .json({
             jsonrpc: "2.0",
             error: {
               code: -32000,
               message: 'Authentication required',
               data: {
                 type: 'oauth_required',
                 auth_url: `${baseUrl}/.well-known/oauth-authorization-server`
               }
             },
             id: req.body?.id || null
           });
      }
      
      // Store valid auth for session
      if (sessionId) {
        sessionAuthHeaders.set(sessionId, authHeader);
      }
    }
    
    // Handle MCP transport (rest of your existing code)
    let transport: StreamableHTTPServerTransport;
    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
      console.log('Using existing transport for session:', sessionId);
    } else if (req.body?.method === 'initialize') {
      console.log('Creating new transport for initialize request');
      const newSessionId = sessionId || crypto.randomUUID();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
        onsessioninitialized: (id) => {
          transports[id] = transport;
          console.log('Initialized new MCP session:', id);
          
          if (authHeader) {
            sessionAuthHeaders.set(id, authHeader);
          }
        }
      });
      await mcpServer.connect(transport);
    } else {
      console.log('Invalid MCP request - no session and not initialize');
      return res.status(400).json({ 
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: 'Invalid request or missing session'
        },
        id: req.body?.id || null
      });
    }
    
    console.log('Processing MCP request through transport');
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error('MCP request error:', error);
    res.status(500).json({ 
      jsonrpc: "2.0",
      error: {
        code: -32603,
        message: 'Internal server error',
        data: error instanceof Error ? error.message : 'Unknown error'
      },
      id: req.body?.id || null
    });
  }
};

// Also add an endpoint to test what methods Claude.ai is calling
app.post('/debug/mcp-test', (req, res) => {
  console.log('=== DEBUG MCP Test Request ===');
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  console.log('Body:', JSON.stringify(req.body, null, 2));
  
  res.json({
    received_method: req.body?.method,
    user_agent: req.headers['user-agent'],
    has_auth: !!(req.headers['authorization'] || req.headers['Authorization']),
    timestamp: new Date().toISOString()
  });
});

// Also add CORS headers to handle Claude.ai's preflight requests
app.options('/mcp', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': req.headers['origin'] || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, mcp-session-id, Accept, User-Agent',
    'Access-Control-Max-Age': '86400'
  }).status(200).end();
});

// Update your existing handler registration
app.post('/mcp', mcpHandler);

// OAuth endpoints - FIXED: Using proper Express handler pattern
const authHandler = async (req: any, res: any) => {
  const state = crypto.randomBytes(32).toString('hex');
  const userId = req.query.user_id as string;
  
  if (!userId) {
    return res.status(400).json({ error: 'user_id parameter required' });
  }
  
  console.log('Setting session state:', state);
  req.session.state = state;
  req.session.userId = userId;
  
  // Force session save
  req.session.save((err: any) => {
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

const oauthCallbackHandler = async (req: any, res: any) => {
  const { code, state } = req.query;
  
  console.log('=== OAuth Callback ===');
  console.log('Query state:', state);
  console.log('Session state:', req.session.state);
  console.log('Session oauthState:', JSON.stringify(req.session.oauthState, null, 2));
  console.log('Authorization code received:', code ? 'yes' : 'no');
  
  try {
    // Check if this is an MCP OAuth flow (has oauthState) or original flow (has state)
    if (req.session.oauthState) {
      // This is the new MCP OAuth flow
      console.log('Processing MCP OAuth callback');
      
      const oauthState = req.session.oauthState;
      const clientId = oauthState.client_id;
      const redirectUri = oauthState.redirect_uri;
      const clientState = oauthState.state;
      const codeChallenge = oauthState.code_challenge;
      
      if (!code) {
        console.error('Missing authorization code from Google');
        return res.status(400).json({ error: 'Missing authorization code' });
      }
      
      // Exchange Google authorization code for tokens
      console.log('Exchanging Google code for tokens...');
      try {
        // Create a temporary user ID for this OAuth flow
        const tempUserId = `temp_${clientId}_${Date.now()}`;
        
        // Use your existing GoogleSheetsService to handle the OAuth callback
        await sheetsService.handleOAuthCallback(tempUserId, code as string);
        console.log('Successfully exchanged Google code for tokens');
        
        // Get the tokens that were just stored
        const googleTokens = await tokenManager.getTokens(tempUserId);
        if (googleTokens) {
          // Store the Google tokens associated with this OAuth client
          clientGoogleTokens.set(clientId, googleTokens);
          console.log('Stored Google tokens for client:', clientId);
        } else {
          console.error('Failed to retrieve Google tokens after exchange');
        }
        
        // Clean up the temporary user tokens
        // (In production, you might want to clean this up differently)
        
      } catch (error) {
        console.error('Failed to exchange Google code:', error);
        return res.status(500).json({ error: 'Failed to exchange authorization code' });
      }
      
      // Generate authorization code for the MCP client
      const authCode = crypto.randomBytes(32).toString('hex');
      
      // Store the auth code with all necessary information
      authCodes.set(authCode, {
        client_id: clientId,
        code_challenge: codeChallenge,
        expires_at: Date.now() + 600000, // 10 minutes
        google_code: code,
        created_at: Date.now()
      });
      
      console.log('Stored auth code:', authCode);
      
      // Clean up session
      delete req.session.oauthState;
      
      // Redirect back to the MCP client with the authorization code
      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.append('code', authCode);
      if (clientState) {
        redirectUrl.searchParams.append('state', clientState);
      }
      
      console.log('Redirecting MCP client to:', redirectUrl.toString());
      res.redirect(redirectUrl.toString());
      
    } else if (req.session.state) {
      // This is the original manual OAuth flow
      console.log('Processing original OAuth callback');
      
      if (!state || state !== req.session.state) {
        console.error('State mismatch in original flow:', { 
          queryState: state, 
          sessionState: req.session.state
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
      
      const userId = req.session.userId;
      if (!userId) {
        console.error('Missing userId in original flow');
        return res.status(400).json({ error: 'Missing userId' });
      }
      
      console.log('Attempting OAuth callback with userId:', userId);
      await sheetsService.handleOAuthCallback(userId, code as string);
      console.log('OAuth callback successful');
      
      // Clean up session
      delete req.session.state;
      delete req.session.userId;
      
      res.json({ success: true, message: 'Successfully connected to Google Sheets' });
    } else {
      console.error('No OAuth state found in session');
      return res.status(400).json({ 
        error: 'No OAuth state found',
        debug: {
          sessionExists: !!req.session,
          hasState: !!req.session?.state,
          hasOAuthState: !!req.session?.oauthState
        }
      });
    }
    
  } catch (error) {
    console.error('=== OAuth Callback Error ===');
    console.error('Error:', error);
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
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    scopes_supported: ['read', 'write', 'sheets:access'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    service_documentation: `${baseUrl}/docs`,
    // Add this to indicate auth is required
    require_auth_for_all_operations: true
  });
});

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.json({
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    scopes_supported: ['read', 'write', 'sheets:access'],
    bearer_methods_supported: ['header'],
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


// Enhanced OAuth registration endpoint with Claude.ai specific handling
const oauthRegisterHandler = async (req: any, res: any) => {
  try {
    console.log('=== OAuth Registration Request ===');
    console.log('Request headers:', JSON.stringify(req.headers, null, 2));
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    console.log('User-Agent:', req.headers['user-agent']);
    
    // Validate required fields
    const { redirect_uris, grant_types = ['authorization_code'] } = req.body;
    
    // Claude.ai specific redirect URIs
    const claudeRedirectUris = [
      'https://claude.ai/api/mcp/auth_callback',
      'https://claude.ai/api/oauth/callback',
      'https://claude.ai/oauth/callback'
    ];
    
    // Allow Claude.ai's redirect URIs or provided ones
    let validRedirectUris = redirect_uris;
    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      console.log('No redirect_uris provided, using Claude.ai defaults');
      validRedirectUris = claudeRedirectUris;
    }
    
    // Validate redirect URIs
    for (const uri of validRedirectUris) {
      try {
        const url = new URL(uri);
        // Allow Claude.ai and localhost URIs
        const isValid = (
          url.hostname === 'claude.ai' ||
          url.hostname === 'localhost' ||
          url.protocol === 'https:'
        );
        
        if (!isValid) {
          console.error('Invalid redirect URI:', uri);
          return res.status(400).json({
            error: 'invalid_redirect_uri',
            error_description: `Invalid redirect URI: ${uri}. Must be HTTPS or Claude.ai domain.`
          });
        }
      } catch (error) {
        console.error('Malformed redirect URI:', uri);
        return res.status(400).json({
          error: 'invalid_redirect_uri',
          error_description: `Malformed redirect URI: ${uri}`
        });
      }
    }

    // Generate client credentials with longer expiry for Claude.ai
    const clientId = crypto.randomBytes(16).toString('hex');
    const clientSecret = crypto.randomBytes(32).toString('hex');
    const issuedAt = Math.floor(Date.now() / 1000);

    // Build client metadata response
    const clientMetadata = {
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: issuedAt,
      client_secret_expires_at: 0, // Never expires
      redirect_uris: validRedirectUris,
      grant_types,
      response_types: req.body.response_types || ['code'],
      token_endpoint_auth_method: req.body.token_endpoint_auth_method || 'client_secret_basic',
      client_name: req.body.client_name || 'Claude.ai MCP Client',
      scope: req.body.scope || 'read write sheets:access'
    };

    // Store client registration
    registeredClients.set(clientId, clientMetadata);
    
    console.log('Client registered successfully:', clientId);
    console.log('Registered clients now:', Array.from(registeredClients.keys()));

    res.status(201).json(clientMetadata);

  } catch (error) {
    console.error('OAuth registration error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error during client registration'
    });
  }
};

// Enhanced OAuth authorization endpoint with better client lookup
const oauthAuthorizeHandler = (req: any, res: any) => {
  const { 
    client_id, 
    redirect_uri, 
    state, 
    code_challenge, 
    code_challenge_method,
    scope,
    response_type 
  } = req.query;

  console.log('=== OAuth Authorization Request ===');
  console.log('Query parameters:', JSON.stringify(req.query, null, 2));
  console.log('All registered clients:', Array.from(registeredClients.keys()));

  // Validate required parameters
  if (!client_id || !redirect_uri) {
    console.error('Missing required parameters');
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing required parameters: client_id and redirect_uri are required'
    });
  }

  // Check if client is registered
  console.log('Looking up client_id:', client_id);
  let client = registeredClients.get(client_id as string);
  
  // Auto-register Claude.ai clients if not found
  if (!client && (redirect_uri as string).includes('claude.ai')) {
    console.log('Auto-registering Claude.ai client');
    
    // Determine all valid Claude.ai redirect URIs
    const claudeRedirectUris = [
      'https://claude.ai/api/mcp/auth_callback',
      'https://claude.ai/api/oauth/callback',
      'https://claude.ai/oauth/callback',
      redirect_uri as string
    ].filter((uri, index, self) => self.indexOf(uri) === index); // Remove duplicates
    
    const autoClientMetadata = {
      client_id: client_id as string,
      client_secret: crypto.randomBytes(32).toString('hex'),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0, // Never expires
      redirect_uris: claudeRedirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // Claude.ai doesn't send client_secret
      client_name: 'Claude.ai MCP Client (Auto-registered)',
      scope: scope as string || 'read write sheets:access'
    };
    
    registeredClients.set(client_id as string, autoClientMetadata);
    console.log('Auto-registered client for Claude.ai:', client_id);
    console.log('Registered redirect URIs:', autoClientMetadata.redirect_uris);
    
    // Set the client to the newly registered one
    client = autoClientMetadata;
  }
  
  // If still no client found, return error
  if (!client) {
    console.error('Unknown client_id and not Claude.ai:', client_id);
    return res.status(400).json({
      error: 'invalid_client',
      error_description: `Unknown client_id: ${client_id}. Please register first at /oauth/register`
    });
  }

  // Validate redirect URI
  if (!client.redirect_uris.includes(redirect_uri as string)) {
    console.error('Invalid redirect_uri:', redirect_uri);
    console.error('Registered redirect_uris:', client.redirect_uris);
    
    // For Claude.ai, be more lenient and add the redirect URI if it's from claude.ai domain
    if ((redirect_uri as string).includes('claude.ai')) {
      console.log('Adding new Claude.ai redirect URI to client');
      client.redirect_uris.push(redirect_uri as string);
      // Update the stored client
      registeredClients.set(client_id as string, client);
    } else {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `redirect_uri not registered for this client. Registered: ${client.redirect_uris.join(', ')}`
      });
    }
  }

  // Validate response_type if provided
  if (response_type && response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only "code" response type is supported'
    });
  }

  // Validate PKCE if provided
  if (code_challenge) {
    if (!code_challenge_method || code_challenge_method !== 'S256') {
      console.log('Warning: code_challenge_method not S256, got:', code_challenge_method);
      // For Claude.ai compatibility, default to S256 if not specified
      if (!code_challenge_method) {
        console.log('Defaulting to S256 for PKCE');
      } else if (code_challenge_method !== 'S256') {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'code_challenge_method must be S256'
        });
      }
    }
  }

  // Generate a unique state for our OAuth flow
  const oauthStateId = crypto.randomBytes(32).toString('hex');
  
  // Store OAuth state for this client
  req.session.oauthState = {
    client_id: client_id as string,
    redirect_uri: redirect_uri as string,
    state: state as string || '',
    code_challenge: code_challenge as string || '',
    scope: scope as string || client.scope || 'read write sheets:access'
  };

  console.log('Storing OAuth state in session:', {
    client_id: client_id,
    redirect_uri: redirect_uri,
    has_state: !!state,
    has_code_challenge: !!code_challenge
  });

  // Save session before redirect
  req.session.save((err: any) => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).json({ 
        error: 'server_error',
        error_description: 'Failed to save session state' 
      });
    }
    
    console.log('Session saved successfully');
    
    // Redirect to Google OAuth with our state
    const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    googleAuthUrl.searchParams.append('client_id', process.env.GOOGLE_CLIENT_ID!);
    googleAuthUrl.searchParams.append('redirect_uri', process.env.GOOGLE_REDIRECT_URI!);
    googleAuthUrl.searchParams.append('response_type', 'code');
    googleAuthUrl.searchParams.append('scope', 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive.file');
    googleAuthUrl.searchParams.append('state', oauthStateId);
    googleAuthUrl.searchParams.append('access_type', 'offline');
    googleAuthUrl.searchParams.append('prompt', 'consent');

    console.log('Redirecting to Google OAuth');
    res.redirect(googleAuthUrl.toString());
  });
};

// OAuth token endpoint handler - FIXED: Using proper Express handler pattern
const oauthTokenHandler = async (req: any, res: any) => {
  console.log('=== OAuth Token Exchange Request ===');
  console.log('Request Content-Type:', req.headers['content-type']);
  console.log('Request body (raw):', req.body);
  console.log('Request body keys:', req.body ? Object.keys(req.body) : 'undefined');
  console.log('Request headers:', JSON.stringify(req.headers, null, 2));

  try {
    // Handle case where req.body might be undefined or empty
    if (!req.body || typeof req.body !== 'object') {
      console.error('Request body is missing or invalid:', req.body);
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Request body is missing or malformed. Expected form-encoded or JSON data.'
      });
    }

    const { 
      grant_type, 
      code, 
      redirect_uri, 
      client_id, 
      client_secret,
      code_verifier 
    } = req.body;

    console.log('Extracted parameters:', {
      grant_type,
      code: code ? 'present' : 'missing',
      redirect_uri,
      client_id,
      client_secret: client_secret ? 'present' : 'missing',
      code_verifier: code_verifier ? 'present' : 'missing'
    });

    // Validate required parameters
    if (!grant_type) {
      console.error('Missing grant_type parameter');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing grant_type parameter'
      });
    }

    if (!code) {
      console.error('Missing code parameter');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing code parameter'
      });
    }

    if (!client_id) {
      console.error('Missing client_id parameter');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing client_id parameter'
      });
    }

    // Validate grant type
    if (grant_type !== 'authorization_code') {
      console.error('Unsupported grant type:', grant_type);
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code grant type is supported'
      });
    }

    // Validate client
    console.log('Looking up client_id:', client_id);
    console.log('Registered clients:', Array.from(registeredClients.keys()));
    
    const client = registeredClients.get(client_id);
    if (!client) {
      console.error('Unknown client_id:', client_id);
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Unknown client_id'
      });
    }

    console.log('Found client:', JSON.stringify(client, null, 2));

    // Validate redirect URI if provided
    if (redirect_uri && !client.redirect_uris.includes(redirect_uri)) {
      console.error('Invalid redirect_uri:', redirect_uri);
      console.error('Registered redirect_uris:', client.redirect_uris);
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'redirect_uri not registered for this client'
      });
    }

    // Check if we have a stored authorization code
    console.log('Looking up authorization code:', code);
    console.log('Stored auth codes:', Array.from(authCodes.keys()));
    
    const storedAuthCode = authCodes.get(code);
    if (storedAuthCode) {
      console.log('Found stored auth code:', JSON.stringify(storedAuthCode, null, 2));
      
      // Validate the authorization code hasn't expired
      if (storedAuthCode.expires_at < Date.now()) {
        console.error('Authorization code expired');
        authCodes.delete(code); // Clean up expired code
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code has expired'
        });
      }

      // Validate client_id matches
      if (storedAuthCode.client_id !== client_id) {
        console.error('Client ID mismatch in auth code');
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code was not issued to this client'
        });
      }

      // Validate PKCE if code_verifier is provided
      if (code_verifier && storedAuthCode.code_challenge) {
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
        if (hash !== storedAuthCode.code_challenge) {
          console.error('PKCE validation failed');
          console.error('Expected hash:', storedAuthCode.code_challenge);
          console.error('Computed hash:', hash);
          return res.status(400).json({
            error: 'invalid_grant',
            error_description: 'PKCE validation failed'
          });
        }
        console.log('PKCE validation successful');
      }

      // Remove the used authorization code
      authCodes.delete(code);
    } else {
      console.log('No stored auth code found, treating as simple code exchange');
    }

    // Generate access token and refresh token
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');
    const expiresIn = 3600; // 1 hour

    // Store the access token
    accessTokens.set(accessToken, {
      client_id,
      scope: client.scope,
      expires_at: Date.now() + (expiresIn * 1000),
      refresh_token: refreshToken,
      created_at: Date.now()
    });

    console.log('Generated access token:', accessToken);
    console.log('Stored access token info');

    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope: client.scope
    };

    console.log('Sending token response:', JSON.stringify(tokenResponse, null, 2));
    res.json(tokenResponse);

  } catch (error) {
    console.error('=== OAuth Token Exchange Error ===');
    console.error('Error:', error);
    console.error('Error message:', error instanceof Error ? error.message : 'Unknown error');
    console.error('Error stack:', error instanceof Error ? error.stack : 'No stack trace');
    
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error during token exchange',
      debug: process.env.NODE_ENV === 'development' ? {
        message: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      } : undefined
    });
  }
};

// Register the OAuth endpoints - add these after your existing OAuth endpoints
app.post('/oauth/register', oauthRegisterHandler);
app.get('/oauth/authorize', oauthAuthorizeHandler);
app.post('/oauth/token', oauthTokenHandler);

// Add a debug endpoint to see registered clients
app.get('/debug/clients', (req, res) => {
  const clients = Array.from(registeredClients.entries()).map(([id, client]) => ({
    client_id: id,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    created_at: client.client_id_issued_at
  }));
  
  res.json({
    total_clients: clients.length,
    clients: clients
  });
});

// Add a debug endpoint to clear all clients (for testing)
app.post('/debug/clear-clients', (req, res) => {
  const count = registeredClients.size;
  registeredClients.clear();
  res.json({ 
    message: `Cleared ${count} registered clients` 
  });
});


// Add session type declaration (add this to extend the session type)
declare module 'express-session' {
  interface SessionData {
    state?: string;
    userId?: string;
    oauthState?: {
      client_id: string;
      redirect_uri: string;
      state: string;
      code_challenge: string;
      scope: string;
    };
  }
}

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