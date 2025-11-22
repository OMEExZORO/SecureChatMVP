import { useEffect, useState } from 'react';

interface AdminMessage {
  type: string;
  senderId: string;
  recipientId: string;
  counter: number;
  timestamp: number;
  cipher: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  sha256_plaintext: string;
}

export default function AdminPanel() {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<AdminMessage[]>([]);

  useEffect(() => {
    console.log('AdminPanel: Attempting to connect to WebSocket...');
    const websocket = new WebSocket('ws://localhost:8080');

    websocket.onopen = () => {
      console.log('AdminPanel: WebSocket opened, sending ADMIN_CONNECT');
      // Send admin connection request
      websocket.send(JSON.stringify({ type: 'ADMIN_CONNECT' }));
      setConnected(true);
      console.log('Admin connected to server');
    };

    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('Admin received:', data);

      if (data.type === 'ADMIN_MSG') {
        setMessages(prev => [...prev, data]);
      } else if (data.type === 'ADMIN_ACK') {
        console.log('Admin acknowledged:', data.message);
      }
    };

    websocket.onclose = () => {
      setConnected(false);
      console.log('Admin disconnected');
    };

    websocket.onerror = (error) => {
      console.error('Admin WebSocket error:', error);
      setConnected(false);
    };

    return () => {
      console.log('AdminPanel: Cleaning up WebSocket connection');
      websocket.close();
    };
  }, []);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold mb-2">🔒 Admin Monitoring Panel</h1>
          <p className="text-gray-400">
            Viewing encrypted messages only - Server never decrypts
          </p>
          <div className="mt-2 flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm">{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>

        {/* Info Banner */}
        <div className="bg-blue-900 border border-blue-700 rounded-lg p-4 mb-6">
          <p className="text-sm">
            <span className="font-bold">Note:</span> This panel demonstrates that the server operates in <strong>zero-knowledge mode</strong>. 
            All messages shown here are encrypted and cannot be read by the server or admin.
          </p>
        </div>

        {/* Messages List */}
        <div className="space-y-4">
          {messages.length === 0 && (
            <div className="text-center text-gray-500 py-12">
              No messages intercepted yet. Waiting for encrypted traffic...
            </div>
          )}

          {messages.map((msg, idx) => (
            <div key={idx} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              {/* Header */}
              <div className="flex justify-between items-start mb-3">
                <div>
                  <span className="text-blue-400 font-mono text-sm">{msg.senderId}</span>
                  <span className="text-gray-500 mx-2">→</span>
                  <span className="text-green-400 font-mono text-sm">{msg.recipientId}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <span className="bg-purple-900 text-purple-300 px-2 py-1 rounded text-xs font-mono">
                    {msg.cipher}
                  </span>
                  <span className="text-gray-500 text-xs">
                    #{msg.counter}
                  </span>
                </div>
              </div>

              {/* Encrypted Data */}
              <div className="space-y-2 text-xs font-mono">
                <div className="grid grid-cols-4 gap-2">
                  <div className="col-span-1 text-gray-400">IV:</div>
                  <div className="col-span-3 text-yellow-400 break-all">{msg.iv || 'N/A'}</div>
                </div>

                <div className="grid grid-cols-4 gap-2">
                  <div className="col-span-1 text-gray-400">Ciphertext:</div>
                  <div className="col-span-3 relative group">
                    <div className="text-red-400 break-all truncate">
                      {msg.ciphertext.substring(0, 100)}...
                    </div>
                    <button
                      onClick={() => copyToClipboard(msg.ciphertext)}
                      className="absolute right-0 top-0 bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded text-white opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      Copy
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-4 gap-2">
                  <div className="col-span-1 text-gray-400">Auth Tag:</div>
                  <div className="col-span-3 text-orange-400 break-all">{msg.authTag || 'N/A'}</div>
                </div>

                <div className="grid grid-cols-4 gap-2">
                  <div className="col-span-1 text-gray-400">SHA-256:</div>
                  <div className="col-span-3 text-green-400 break-all">{msg.sha256_plaintext}</div>
                </div>
              </div>

              {/* Footer */}
              <div className="mt-3 pt-3 border-t border-gray-700 text-xs text-gray-500">
                <span>Timestamp: {new Date(msg.timestamp * 1000).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
