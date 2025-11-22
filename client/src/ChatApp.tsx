import { useState, useEffect } from 'react';
import { WebSocketClient } from './lib/websocket';
import { Message, WSMessage, Conversation } from './types';
import {
  generateSalt,
  deriveKey,
  encryptMessage,
  decryptMessage,
  verifyHash,
  createCanonicalAAD,
  saltToBase64,
  base64ToSalt,
} from './lib/crypto';
import './index.css';

const WS_URL = 'ws://localhost:8080/ws';

function App() {
  const [wsClient] = useState(() => new WebSocketClient(WS_URL));
  const [connected, setConnected] = useState(false);
  const [userId, setUserId] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [error, setError] = useState('');
  const [showLogin, setShowLogin] = useState(true);
  const [showPassphraseSetup, setShowPassphraseSetup] = useState(false);

  useEffect(() => {
    wsClient.onConnect(() => {
      setConnected(true);
      setError('');
    });

    wsClient.onDisconnect(() => {
      setConnected(false);
    });

    wsClient.onMessage(handleIncomingMessage);

    return () => {
      wsClient.disconnect();
    };
  }, []);

  const handleIncomingMessage = async (msg: WSMessage) => {
    console.log('Handling message:', msg);

    if (msg.type === 'HELLO_ACK') {
      console.log('Connected as:', msg.userId);
    } else if (msg.type === 'MSG') {
      await handleReceivedMessage(msg);
    } else if (msg.type === 'REJECT') {
      setError(`Message rejected: ${msg.reason}`);
    } else if (msg.type === 'ERROR') {
      setError(`Server error: ${msg.message}`);
    }
  };

  const handleReceivedMessage = async (msg: WSMessage) => {
    if (!conversation || !conversation.encryptionKey) {
      setError('Cannot decrypt: encryption key not set');
      return;
    }

    try {
      const aad = createCanonicalAAD({
        senderId: msg.senderId!,
        recipientId: msg.recipientId!,
        counter: msg.counter!,
      });

      const plaintext = await decryptMessage(
        msg.iv!,
        msg.ciphertext!,
        msg.authTag!,
        conversation.encryptionKey,
        aad
      );

      const verified = await verifyHash(plaintext, msg.sha256_plaintext!);

      const message: Message = {
        senderId: msg.senderId!,
        recipientId: msg.recipientId!,
        counter: msg.counter!,
        timestamp: msg.timestamp!,
        cipher: msg.cipher!,
        iv: msg.iv!,
        aad,
        ciphertext: msg.ciphertext!,
        authTag: msg.authTag!,
        sha256_plaintext: msg.sha256_plaintext!,
        plaintext,
        verified,
      };

      setMessages(prev => [...prev, message]);
    } catch (error) {
      console.error('Failed to decrypt message:', error);
      setError('Failed to decrypt message');
    }
  };

  const handleLogin = async () => {
    if (!userId.trim()) {
      setError('Please enter a user ID');
      return;
    }

    try {
      await wsClient.connect();
      wsClient.send({ type: 'HELLO', userId });
      setShowLogin(false);
    } catch (error) {
      // Allow offline mode for UI testing
      console.warn('Backend server not running. Using offline mode.');
      setError('');
      setShowLogin(false);
    }
  };

  const handleSetupEncryption = async () => {
    if (!recipientId.trim() || !passphrase.trim()) {
      setError('Please enter recipient ID and passphrase');
      return;
    }

    if (passphrase.length < 8) {
      setError('Passphrase must be at least 8 characters');
      return;
    }

    try {
      // Check if salt exists in localStorage
      const conversationId = [userId, recipientId].sort().join('_');
      let salt: Uint8Array;
      const savedSalt = localStorage.getItem(`salt_${conversationId}`);

      if (savedSalt) {
        salt = base64ToSalt(savedSalt);
      } else {
        salt = await generateSalt();
        localStorage.setItem(`salt_${conversationId}`, saltToBase64(salt));
      }

      const encryptionKey = await deriveKey(passphrase, salt);

      setConversation({
        userId: recipientId,
        counter: 0,
        encryptionKey,
        salt,
      });

      setShowPassphraseSetup(false);
      setError('');
    } catch (error) {
      console.error('Failed to setup encryption:', error);
      setError('Failed to setup encryption key');
    }
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || !conversation || !conversation.encryptionKey) {
      return;
    }

    try {
      const newCounter = conversation.counter + 1;

      const aad = createCanonicalAAD({
        senderId: userId,
        recipientId: recipientId,
        counter: newCounter,
      });

      const encrypted = await encryptMessage(
        inputMessage,
        conversation.encryptionKey,
        aad
      );

      const message: WSMessage = {
        type: 'MSG',
        senderId: userId,
        recipientId: recipientId,
        counter: newCounter,
        timestamp: Math.floor(Date.now() / 1000),
        cipher: 'AES-256-GCM',
        iv: encrypted.iv,
        aad,
        ciphertext: encrypted.ciphertext,
        authTag: encrypted.authTag,
        sha256_plaintext: encrypted.sha256,
      };

      // Try to send via WebSocket if connected
      try {
        if (wsClient.isConnected()) {
          wsClient.send(message);
        } else {
          console.warn('Not connected to server. Message stored locally only.');
        }
      } catch (err) {
        console.warn('Failed to send to server:', err);
      }

      // Add to local messages
      const localMessage: Message = {
        senderId: userId,
        recipientId: recipientId,
        counter: newCounter,
        timestamp: Math.floor(Date.now() / 1000),
        cipher: 'AES-256-GCM',
        iv: encrypted.iv,
        aad,
        ciphertext: encrypted.ciphertext,
        authTag: encrypted.authTag,
        sha256_plaintext: encrypted.sha256,
        plaintext: inputMessage,
        verified: true,
      };
      setMessages(prev => [...prev, localMessage]);

      // Update counter
      setConversation(prev => prev ? { ...prev, counter: newCounter } : null);
      setInputMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
      setError('Failed to send message');
    }
  };

  if (showLogin) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <h1 className="text-2xl font-bold text-center mb-6">Secure Chat</h1>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Your User ID
              </label>
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your user ID"
                onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
              />
            </div>
            {error && (
              <div className="text-red-600 text-sm">{error}</div>
            )}
            <button
              onClick={handleLogin}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Connect
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!conversation) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <h1 className="text-2xl font-bold text-center mb-6">Setup Encryption</h1>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Recipient User ID
              </label>
              <input
                type="text"
                value={recipientId}
                onChange={(e) => setRecipientId(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter recipient user ID"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Shared Passphrase (min 8 chars)
              </label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter shared passphrase"
                onKeyPress={(e) => e.key === 'Enter' && handleSetupEncryption()}
              />
            </div>
            <div className="text-xs text-gray-600 bg-yellow-50 p-3 rounded">
              ⚠️ Both users must use the same passphrase. Share it securely out-of-band.
            </div>
            {error && (
              <div className="text-red-600 text-sm">{error}</div>
            )}
            <button
              onClick={handleSetupEncryption}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Setup Encryption
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-4xl mx-auto p-4 h-screen flex flex-col">
        {/* Header */}
        <div className="bg-white rounded-t-lg shadow-lg p-4 flex justify-between items-center">
          <div>
            <h1 className="text-xl font-bold">Secure Chat</h1>
            <p className="text-sm text-gray-600">
              {userId} ↔ {recipientId}
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-yellow-500'}`} />
            <span className="text-sm">{connected ? 'Connected' : 'Offline Mode'}</span>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 bg-white shadow-lg overflow-y-auto p-4 space-y-3">
          {!connected && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 mb-3">
              <p className="text-sm text-yellow-800">
                ⚠️ <strong>Offline Mode:</strong> Backend server not running. Messages are encrypted locally but won't be sent to other users. Start the backend server to enable real-time messaging.
              </p>
            </div>
          )}
          {messages.length === 0 && (
            <div className="text-center text-gray-500 mt-8">
              No messages yet. Start the conversation!
            </div>
          )}
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex ${msg.senderId === userId ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                  msg.senderId === userId
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-800'
                }`}
              >
                <p className="break-words">{msg.plaintext}</p>
                <div className="flex items-center justify-between mt-1 text-xs opacity-75">
                  <span>#{msg.counter}</span>
                  {msg.verified !== undefined && (
                    <span className={msg.verified ? 'text-green-300' : 'text-red-300'}>
                      {msg.verified ? '✓ PASS' : '✗ FAIL'}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <div className="bg-white rounded-b-lg shadow-lg p-4">
          {error && (
            <div className="text-red-600 text-sm mb-2">{error}</div>
          )}
          <div className="flex space-x-2">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Type a message..."
            />
            <button
              onClick={handleSendMessage}
              disabled={!inputMessage.trim()}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors disabled:bg-gray-400"
            >
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
