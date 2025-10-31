export interface Message {
  type: string;
  senderId?: string;
  recipientId?: string;
  counter?: number;
  timestamp?: number;
  iv?: string;
  ciphertext?: string;
  authTag?: string;
  sha256_plaintext?: string;
  aad?: { senderId: string; recipientId: string; counter: number };
  cipher?: string;
  reason?: string;
  message?: string;
  userId?: string;
  salt?: string;
}

export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected';

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private onMessageCallback: ((msg: Message) => void) | null = null;
  private onStatusChangeCallback: ((status: ConnectionStatus) => void) | null = null;
  private reconnectTimeout: number | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 2000;

  constructor(url: string) {
    this.url = url;
  }

  connect(userId: string): void {
    if (this.ws) {
      this.ws.close();
    }

    this.updateStatus('connecting');
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
      this.updateStatus('connected');
      
      this.send({
        type: 'HELLO',
        userId: userId,
      });
    };

    this.ws.onmessage = (event) => {
      try {
        const message: Message = JSON.parse(event.data);
        console.log('Received message:', message);
        
        if (this.onMessageCallback) {
          this.onMessageCallback(message);
        }
      } catch (error) {
        console.error('Failed to parse message:', error);
      }
    };

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    this.ws.onclose = () => {
      console.log('WebSocket disconnected');
      this.updateStatus('disconnected');
      this.ws = null;
      
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        console.log(`Reconnecting in ${this.reconnectDelay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        this.reconnectTimeout = window.setTimeout(() => {
          this.connect(userId);
        }, this.reconnectDelay);
      }
    };
  }

  send(message: Message): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.error('WebSocket is not connected');
      throw new Error('WebSocket is not connected');
    }
  }

  disconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    
    this.reconnectAttempts = this.maxReconnectAttempts;
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    
    this.updateStatus('disconnected');
  }

  onMessage(callback: (msg: Message) => void): void {
    this.onMessageCallback = callback;
  }

  onStatusChange(callback: (status: ConnectionStatus) => void): void {
    this.onStatusChangeCallback = callback;
  }

  private updateStatus(status: ConnectionStatus): void {
    if (this.onStatusChangeCallback) {
      this.onStatusChangeCallback(status);
    }
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}
