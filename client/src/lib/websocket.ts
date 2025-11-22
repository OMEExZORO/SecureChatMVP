import { WSMessage } from '../types';

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private messageHandlers: Array<(message: WSMessage) => void> = [];
  private connectionHandlers: Array<() => void> = [];
  private disconnectionHandlers: Array<() => void> = [];
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 3000;

  constructor(url: string) {
    this.url = url;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          this.connectionHandlers.forEach(handler => handler());
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message: WSMessage = JSON.parse(event.data);
            console.log('Received message:', message);
            this.messageHandlers.forEach(handler => handler(message));
          } catch (error) {
            console.error('Failed to parse message:', error);
          }
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          this.disconnectionHandlers.forEach(handler => handler());
          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  private attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
      setTimeout(() => {
        this.connect().catch(error => {
          console.error('Reconnection failed:', error);
        });
      }, this.reconnectDelay);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }

  send(message: WSMessage) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
      console.log('Sent message:', message);
    } else {
      console.error('WebSocket is not connected');
      throw new Error('WebSocket is not connected');
    }
  }

  onMessage(handler: (message: WSMessage) => void) {
    this.messageHandlers.push(handler);
    // Return a cleanup function to remove this handler
    return () => {
      const index = this.messageHandlers.indexOf(handler);
      if (index > -1) {
        this.messageHandlers.splice(index, 1);
      }
    };
  }

  onConnect(handler: () => void) {
    this.connectionHandlers.push(handler);
  }

  onDisconnect(handler: () => void) {
    this.disconnectionHandlers.push(handler);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}
