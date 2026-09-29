import { Server as HttpServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import jwt from 'jsonwebtoken';
import { db, DBUser } from '../db/database';
import { Alert, Finding, NormalizedEvent, RiskScore, SecurityLog } from '../../src/types/siem';

const JWT_SECRET = process.env.JWT_SECRET || 'siem_soc_jwt_secure_secret_key_2026';

interface AuthenticatedClient {
  ws: WebSocket;
  user: DBUser;
  isSOCAdmin: boolean;
  connectedAt: string;
}

export class WebSocketManager {
  private static instance: WebSocketManager;
  private wss: WebSocketServer | null = null;
  private clients: Map<WebSocket, AuthenticatedClient> = new Map();
  private pingInterval: NodeJS.Timeout | null = null;

  private constructor() {}

  public static getInstance(): WebSocketManager {
    if (!WebSocketManager.instance) {
      WebSocketManager.instance = new WebSocketManager();
    }
    return WebSocketManager.instance;
  }

  public initialize(server: HttpServer) {
    if (this.wss) {
      return;
    }

    this.wss = new WebSocketServer({
      server,
      path: '/ws/alerts',
    });

    this.wss.on('connection', (ws: WebSocket, req) => {
      try {
        const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
        const token = url.searchParams.get('token') || (req.headers['sec-websocket-protocol'] as string);

        let user: DBUser | undefined;

        if (token) {
          try {
            const decoded = jwt.verify(token, JWT_SECRET) as { id: number; username: string };
            user = db.getUserById(decoded.id) || db.getUserByUsername(decoded.username);
          } catch (err) {
            console.warn('[WS] Token verification failed on connection:', err);
          }
        }

        // If not authenticated via query token, set default guest state or wait for auth message
        const isSOCAdmin = Boolean(user && (user.role === 'ADMIN' || user.role === 'SECURITY_ANALYST'));

        const clientData: AuthenticatedClient = {
          ws,
          user: user || {
            id: 0,
            username: 'anonymous',
            fullName: 'Anonymous Client',
            email: '',
            department: 'General',
            role: 'VIEWER',
            status: 'ACTIVE',
            createdAt: new Date().toISOString(),
            passwordHash: '',
          },
          isSOCAdmin,
          connectedAt: new Date().toISOString(),
        };

        this.clients.set(ws, clientData);

        // Send connection ACK
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(
            JSON.stringify({
              type: 'CONNECTED',
              payload: {
                role: clientData.user.role,
                isSOCAdmin,
                message: isSOCAdmin
                  ? 'Connected to SOC Real-Time Threat Stream'
                  : 'Connected to Employee Document Workspace',
              },
            })
          );
        }

        ws.on('message', (messageRaw: string) => {
          try {
            const data = JSON.parse(messageRaw.toString());
            if (data.type === 'AUTH' && data.token) {
              const decoded = jwt.verify(data.token, JWT_SECRET) as { id: number; username: string };
              const authedUser = db.getUserById(decoded.id) || db.getUserByUsername(decoded.username);
              if (authedUser) {
                const isAdmin = authedUser.role === 'ADMIN' || authedUser.role === 'SECURITY_ANALYST';
                clientData.user = authedUser;
                clientData.isSOCAdmin = isAdmin;
                ws.send(
                  JSON.stringify({
                    type: 'AUTH_SUCCESS',
                    payload: { role: authedUser.role, isSOCAdmin: isAdmin },
                  })
                );
              }
            } else if (data.type === 'PING') {
              ws.send(JSON.stringify({ type: 'PONG', timestamp: Date.now() }));
            }
          } catch (e) {
            // ignore malformed message
          }
        });

        ws.on('close', () => {
          this.clients.delete(ws);
        });

        ws.on('error', () => {
          this.clients.delete(ws);
        });
      } catch (err) {
        console.error('[WS] Connection handler error:', err);
      }
    });

    // Keepalive ping interval every 30s
    this.pingInterval = setInterval(() => {
      this.clients.forEach((client, ws) => {
        if (ws.readyState === WebSocket.OPEN) {
          try {
            ws.ping();
          } catch {
            this.clients.delete(ws);
          }
        } else {
          this.clients.delete(ws);
        }
      });
    }, 30000);
  }

  // Broadcast to Admin / Security Analyst sockets ONLY
  public broadcastToAdmins(message: { type: string; payload: any }) {
    const raw = JSON.stringify(message);
    this.clients.forEach((client, ws) => {
      if (client.isSOCAdmin && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(raw);
        } catch (err) {
          console.error('[WS] Error broadcasting to admin socket:', err);
        }
      }
    });
  }

  // Explicit broadcast methods
  public broadcastNewAlert(alert: Alert) {
    this.broadcastToAdmins({
      type: 'NEW_ALERT',
      payload: alert,
    });
  }

  public broadcastAlertUpdated(alert: Alert) {
    this.broadcastToAdmins({
      type: 'ALERT_UPDATED',
      payload: alert,
    });
  }

  public broadcastNewFinding(finding: Finding) {
    this.broadcastToAdmins({
      type: 'NEW_FINDING',
      payload: finding,
    });
  }

  public broadcastRiskScore(riskScore: RiskScore) {
    this.broadcastToAdmins({
      type: 'RISK_SCORE_UPDATED',
      payload: riskScore,
    });
  }

  public broadcastNewEvent(event: NormalizedEvent) {
    this.broadcastToAdmins({
      type: 'NEW_EVENT',
      payload: event,
    });
  }

  public getConnectedStats() {
    let adminCount = 0;
    let employeeCount = 0;
    this.clients.forEach((c) => {
      if (c.isSOCAdmin) adminCount++;
      else employeeCount++;
    });
    return { total: this.clients.size, adminCount, employeeCount };
  }
}

export const wsManager = WebSocketManager.getInstance();
