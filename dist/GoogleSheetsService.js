"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleSheetsService = void 0;
const googleapis_1 = require("googleapis");
class GoogleSheetsService {
    oauth2Client;
    tokenManager;
    constructor(tokenManager) {
        this.tokenManager = tokenManager;
        this.oauth2Client = new googleapis_1.google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
    }
    getAuthUrl(state) {
        const scopes = [
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive.file'
        ];
        return this.oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopes,
            include_granted_scopes: true,
            state: state,
            prompt: 'consent'
        });
    }
    async handleOAuthCallback(userId, code) {
        const { tokens } = await this.oauth2Client.getToken(code);
        await this.tokenManager.storeTokens(userId, {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token || undefined,
            expiry_date: tokens.expiry_date || Date.now() + 3600000,
            scope: tokens.scope?.split(' ') || []
        });
    }
    async createSpreadsheet(userId, title) {
        const sheets = await this.getSheetsClient(userId);
        const response = await sheets.spreadsheets.create({
            requestBody: {
                properties: { title }
            }
        });
        return {
            id: response.data.spreadsheetId,
            url: `https://docs.google.com/spreadsheets/d/${response.data.spreadsheetId}`
        };
    }
    async readData(userId, spreadsheetId, range) {
        const sheets = await this.getSheetsClient(userId);
        const response = await sheets.spreadsheets.values.get({
            spreadsheetId,
            range
        });
        return response.data.values || [];
    }
    async writeData(userId, spreadsheetId, range, values) {
        const sheets = await this.getSheetsClient(userId);
        const response = await sheets.spreadsheets.values.update({
            spreadsheetId,
            range,
            valueInputOption: 'RAW',
            requestBody: { values }
        });
        return response.data.updatedCells || 0;
    }
    async getSheetsClient(userId) {
        const tokens = await this.tokenManager.getTokens(userId);
        if (!tokens) {
            throw new Error('No tokens found for user');
        }
        // Convert TokenData to Credentials format
        const credentials = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expiry_date: tokens.expiry_date,
            scope: tokens.scope.join(' ') // Convert array to space-separated string
        };
        this.oauth2Client.setCredentials(credentials);
        return googleapis_1.google.sheets({ version: 'v4', auth: this.oauth2Client });
    }
}
exports.GoogleSheetsService = GoogleSheetsService;
