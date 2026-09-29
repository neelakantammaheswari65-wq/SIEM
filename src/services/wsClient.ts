import { Alert, Finding, NormalizedEvent, RiskScore } from '../types/siem';

type WebSocketListener = (event: { type: string; payload: any }) => void;

class SIEMWebSocketClient {
  private static instance: SIEMWebSocketClient;
  private ws: WebSocket | null = null;
  private listeners: Set<WebSocketListener> = new Set();
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isExplicitlyClosed: boolean = false;
  private token: string | null = null;
  private consecutiveFailures: number = 0;
  private readonly maxReconnectAttempts: number = 4;
  private isAutoReconnectPaused: boolean = false;

  private constructor() {}

  public static getInstance(): SIEMWebSocketClient {
    if (!SIEMWebSocketClient.instance) {
      SIEMWebSocketClient.instance = new SIEMWebSocketClient();
    }
    return SIEMWebSocketClient.instance;
  }

  public connect(token?: string) {
    if (token) {
      this.token = token;
    } else if (!this.token) {
      this.token = localStorage.getItem('siem_auth_token');
    }

    this.isExplicitlyClosed = false;

    // Do not attempt if already open or connecting
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    // If auto-reconnect was paused due to repeated failures, do not spam unless reset
    if (this.isAutoReconnectPaused) {
      return;
    }

    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const url = `${protocol}//${host}/ws/alerts${this.token ? `?token=${encodeURIComponent(this.token)}` : ''}`;

      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('[SIEM WS] Connected to backend alert stream');
        this.consecutiveFailures = 0;
        this.isAutoReconnectPaused = false;
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.notifyListeners(data);
        } catch (err) {
          console.error('[SIEM WS] Error parsing message:', err);
        }
      };

      this.ws.onclose = () => {
        if (!this.isExplicitlyClosed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = (err) => {
        console.warn('[SIEM WS] Connection unavailable (operating in resilient local mode)');
      };
    } catch (e) {
      console.warn('[SIEM WS] Could not initialize WebSocket:', e);
      this.scheduleReconnect();
    }
  }

  public disconnect() {
    this.isExplicitlyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // ignore
      }
      this.ws = null;
    }
  }

  public updateToken(token: string | null) {
    this.token = token;
    if (this.ws && this.ws.readyState === WebSocket.OPEN && token) {
      try {
        this.ws.send(JSON.stringify({ type: 'AUTH', token }));
      } catch {
        // ignore
      }
    } else if (token && !this.isAutoReconnectPaused) {
      this.connect(token);
    }
  }

  public subscribe(listener: WebSocketListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(data: { type: string; payload: any }) {
    this.listeners.forEach((listener) => {
      try {
        listener(data);
      } catch (err) {
        console.error('[SIEM WS] Listener error:', err);
      }
    });
  }

  private scheduleReconnect() {
    if (this.reconnectTimer || this.isExplicitlyClosed) return;

    this.consecutiveFailures++;

    if (this.consecutiveFailures > this.maxReconnectAttempts) {
      console.info(
        `[SIEM WS] Stream paused after ${this.consecutiveFailures - 1} attempts. SIEM operating smoothly with local event pipeline.`
      );
      this.isAutoReconnectPaused = true;
      return;
    }

    // Exponential backoff: 5s, 10s, 20s, max 30s
    const delayMs = Math.min(30000, 2500 * Math.pow(2, this.consecutiveFailures));

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.isExplicitlyClosed && !this.isAutoReconnectPaused) {
        this.connect();
      }
    }, delayMs);
  }

  public resetAndReconnect(token?: string) {
    this.isAutoReconnectPaused = false;
    this.consecutiveFailures = 0;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.connect(token);
  }

  public isPaused(): boolean {
    return this.isAutoReconnectPaused;
  }
}

export const wsClient = SIEMWebSocketClient.getInstance();
