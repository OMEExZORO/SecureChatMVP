import { useState, useEffect, useRef } from 'react';
import { WebSocketClient, ConnectionStatus, Message } from './lib/websocket';
import {
  deriveKey,
  generateSalt,
  encryptAESGCM,
  decryptAESGCM,
  sha256Hash,
  encryptXOR,
  decryptXOR,
  encryptCaesar,
  decryptCaesar,
  EncryptionStrategy,
} from './lib/crypto';

interface ChatMessage {
  id: string;
  senderId: string;
  recipientId: string;
  text: string;
  counter: number;
  timestamp: number;
  verified: boolean | null;
  verificationStatus: 'PASS' | 'FAIL' | 'PENDING';
  isOutgoing: boolean;
}

interface Conversation {
  userId: string;
  salt: string | null;
  key: CryptoKey | null;
  counter: number;
  lastReceivedCounter: number;
  saltShared: boolean;
}

function App() {
  const [userId, setUserId] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [showPassphraseModal, setShowPassphraseModal] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [encryptionStrategy, setEncryptionStrategy] = useState<EncryptionStrategy>('AES-GCM');
  const [error, setError] = useState('');
  const [pendingPassphrase, setPendingPassphrase] = useState('');
  
  const wsClient = useRef<WebSocketClient | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const getWebSocketUrl = () => {
    const isReplit = window.location.hostname.includes('repl');
    if (isReplit) {
      return `wss://${window.location.hostname.replace(/\.repl\.co$/, '')}.repl.co:8080/ws`;
    }
    return 'ws://localhost:8080/ws';
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleLogin = () => {
    if (!userId.trim()) {
      setError('User ID is required');
      return;
    }

    wsClient.current = new WebSocketClient(getWebSocketUrl());
    
    wsClient.current.onStatusChange((status) => {
      setConnectionStatus(status);
    });

    wsClient.current.onMessage(handleIncomingMessage);
    
    wsClient.current.connect(userId);
    setIsLoggedIn(true);
    setError('');
  };

  const handleSetupConversation = async () => {
    if (!passphrase.trim() || !recipientId.trim()) {
      setError('Passphrase and recipient ID are required');
      return;
    }

    if (conversation && conversation.salt) {
      const key = await deriveKey(passphrase, conversation.salt);
      setConversation(prev => prev ? { ...prev, key, saltShared: true } : null);
      console.log('Derived key from received salt');
    } else {
      const salt = generateSalt();
      
      const key = await deriveKey(passphrase, salt);
      
      setConversation({
        userId: recipientId,
        salt,
        key,
        counter: 0,
        lastReceivedCounter: -1,
        saltShared: false,
      });

      if (wsClient.current && wsClient.current.isConnected()) {
        wsClient.current.send({
          type: 'KEY_SHARE',
          senderId: userId,
          recipientId,
          salt,
        });
        console.log('Sent KEY_SHARE with salt');
      }
    }

    setPendingPassphrase(passphrase);
    setShowPassphraseModal(false);
    setPassphrase('');
    setError('');
  };

  const handleIncomingMessage = async (msg: Message) => {
    console.log('Processing incoming message:', msg);

    if (msg.type === 'HELLO_ACK') {
      console.log('Connected as', msg.userId);
      return;
    }

    if (msg.type === 'REJECT') {
      setError(`Message rejected: ${msg.reason}`);
      return;
    }

    if (msg.type === 'KEY_SHARE' && msg.salt && msg.senderId) {
      console.log('Received KEY_SHARE from', msg.senderId, 'with salt');
      
      setConversation({
        userId: msg.senderId,
        salt: msg.salt,
        key: null,
        counter: 0,
        lastReceivedCounter: -1,
        saltShared: false,
      });
      
      setRecipientId(msg.senderId);
      setShowPassphraseModal(true);
      
      return;
    }

    if (msg.type === 'MSG' && conversation) {
      try {
        if (!msg.counter || !msg.timestamp || !msg.iv || !msg.ciphertext || !msg.authTag || !msg.sha256_plaintext || !msg.senderId || !msg.aad) {
          console.error('Invalid message format');
          return;
        }

        const currentTime = Math.floor(Date.now() / 1000);
        const timeDiff = Math.abs(currentTime - msg.timestamp);
        
        if (timeDiff > 300) {
          console.error('Message timestamp outside allowed window');
          setError('Message rejected: timestamp too old');
          return;
        }

        if (msg.counter <= conversation.lastReceivedCounter) {
          console.error('Counter not monotonic');
          setError('Message rejected: replay attack detected (counter)');
          return;
        }

        let plaintext = '';
        let verificationStatus: 'PASS' | 'FAIL' = 'FAIL';

        if (encryptionStrategy === 'AES-GCM' && conversation.key) {
          plaintext = await decryptAESGCM(
            msg.ciphertext,
            msg.authTag,
            msg.iv,
            conversation.key,
            msg.aad
          );
          
          const computedHash = await sha256Hash(plaintext);
          verificationStatus = computedHash === msg.sha256_plaintext ? 'PASS' : 'FAIL';
        } else if (encryptionStrategy === 'XOR') {
          plaintext = decryptXOR(msg.ciphertext, passphrase);
          const computedHash = await sha256Hash(plaintext);
          verificationStatus = computedHash === msg.sha256_plaintext ? 'PASS' : 'FAIL';
        } else if (encryptionStrategy === 'Caesar') {
          plaintext = decryptCaesar(msg.ciphertext, passphrase);
          const computedHash = await sha256Hash(plaintext);
          verificationStatus = computedHash === msg.sha256_plaintext ? 'PASS' : 'FAIL';
        }

        setConversation(prev => prev ? { ...prev, lastReceivedCounter: msg.counter! } : null);

        const chatMessage: ChatMessage = {
          id: `${msg.senderId}-${msg.counter}-${Date.now()}`,
          senderId: msg.senderId,
          recipientId: msg.recipientId || userId,
          text: plaintext,
          counter: msg.counter,
          timestamp: msg.timestamp,
          verified: verificationStatus === 'PASS',
          verificationStatus,
          isOutgoing: false,
        };

        setMessages(prev => [...prev, chatMessage]);
      } catch (error) {
        console.error('Failed to decrypt message:', error);
        setError('Failed to decrypt message');
      }
    }
  };

  const sendMessage = async () => {
    if (!inputMessage.trim() || !conversation || !wsClient.current || !recipientId) {
      return;
    }

    try {
      const newCounter = conversation.counter + 1;
      const timestamp = Math.floor(Date.now() / 1000);
      const aad = { senderId: userId, recipientId, counter: newCounter };

      let ciphertext = '';
      let iv = '';
      let authTag = '';
      let sha256 = '';

      if (encryptionStrategy === 'AES-GCM' && conversation.key) {
        const result = await encryptAESGCM(inputMessage, conversation.key, aad);
        ciphertext = result.ciphertext;
        iv = result.iv;
        authTag = result.authTag;
        sha256 = result.sha256;
      } else if (encryptionStrategy === 'XOR') {
        ciphertext = encryptXOR(inputMessage, passphrase);
        iv = generateSalt();
        authTag = '';
        sha256 = await sha256Hash(inputMessage);
      } else if (encryptionStrategy === 'Caesar') {
        ciphertext = encryptCaesar(inputMessage, passphrase);
        iv = generateSalt();
        authTag = '';
        sha256 = await sha256Hash(inputMessage);
      }

      const message: Message = {
        type: 'MSG',
        senderId: userId,
        recipientId,
        counter: newCounter,
        timestamp,
        iv,
        ciphertext,
        authTag,
        sha256_plaintext: sha256,
        aad,
        cipher: encryptionStrategy,
      };

      wsClient.current.send(message);

      const chatMessage: ChatMessage = {
        id: `${userId}-${newCounter}-${Date.now()}`,
        senderId: userId,
        recipientId,
        text: inputMessage,
        counter: newCounter,
        timestamp,
        verified: true,
        verificationStatus: 'PASS',
        isOutgoing: true,
      };

      setMessages(prev => [...prev, chatMessage]);
      setConversation(prev => prev ? { ...prev, counter: newCounter } : null);
      setInputMessage('');
      setError('');
    } catch (error) {
      console.error('Failed to send message:', error);
      setError('Failed to send message');
    }
  };

  const handleStartChat = () => {
    if (!recipientId.trim()) {
      setError('Recipient ID is required');
      return;
    }
    setShowPassphraseModal(true);
  };

  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full">
          <h1 className="text-3xl font-bold text-white mb-6 text-center">Secure Chat</h1>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Your User ID
              </label>
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your user ID"
                onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
              />
            </div>
            {error && (
              <div className="text-red-400 text-sm">{error}</div>
            )}
            <button
              onClick={handleLogin}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition"
            >
              Connect
            </button>
          </div>
          <div className="mt-6 text-xs text-gray-400 space-y-2">
            <p><strong>🔒 Security:</strong> AES-256-GCM E2E encryption by default</p>
            <p><strong>✓</strong> SHA-256 integrity verification</p>
            <p><strong>🛡️</strong> Replay protection (counter + timestamp)</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="max-w-6xl mx-auto p-4">
        <div className="bg-gray-800 rounded-lg shadow-xl overflow-hidden">
          <div className="bg-gray-700 p-4 flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold">Secure Chat</h1>
              <p className="text-sm text-gray-300">
                Logged in as: <span className="font-mono">{userId}</span>
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className={`px-3 py-1 rounded text-sm ${
                connectionStatus === 'connected' ? 'bg-green-600' : 
                connectionStatus === 'connecting' ? 'bg-yellow-600' : 'bg-red-600'
              }`}>
                {connectionStatus}
              </span>
              <select
                value={encryptionStrategy}
                onChange={(e) => setEncryptionStrategy(e.target.value as EncryptionStrategy)}
                className="bg-gray-600 px-3 py-1 rounded text-sm"
              >
                <option value="AES-GCM">AES-256-GCM (Default)</option>
                <option value="XOR">XOR (Educational)</option>
                <option value="Caesar">Caesar (Educational)</option>
              </select>
            </div>
          </div>

          {!conversation ? (
            <div className="p-8 text-center">
              <h2 className="text-2xl font-semibold mb-4">Start a Conversation</h2>
              <div className="max-w-md mx-auto space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Recipient User ID
                  </label>
                  <input
                    type="text"
                    value={recipientId}
                    onChange={(e) => setRecipientId(e.target.value)}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded focus:ring-2 focus:ring-blue-500"
                    placeholder="Enter recipient's user ID"
                  />
                </div>
                {error && <div className="text-red-400 text-sm">{error}</div>}
                <button
                  onClick={handleStartChat}
                  className="w-full bg-blue-600 hover:bg-blue-700 font-semibold py-2 px-4 rounded transition"
                >
                  Setup Encryption Key
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="bg-gray-750 px-4 py-2 border-b border-gray-600">
                <p className="text-sm">
                  Chatting with: <span className="font-mono font-semibold">{recipientId}</span>
                  <span className="ml-4 text-xs text-gray-400">
                    Counter: {conversation.counter} | Strategy: {encryptionStrategy}
                  </span>
                </p>
              </div>

              <div className="h-96 overflow-y-auto p-4 space-y-3 bg-gray-850">
                {messages.length === 0 ? (
                  <div className="text-center text-gray-400 mt-8">
                    No messages yet. Start the conversation!
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`flex ${msg.isOutgoing ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                          msg.isOutgoing
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-700 text-white'
                        }`}
                      >
                        <p className="break-words">{msg.text}</p>
                        <div className="mt-1 text-xs opacity-75 flex items-center justify-between gap-2">
                          <span>
                            #{msg.counter} • {new Date(msg.timestamp * 1000).toLocaleTimeString()}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded ${
                              msg.verificationStatus === 'PASS'
                                ? 'bg-green-500 text-white'
                                : 'bg-red-500 text-white'
                            }`}
                          >
                            {msg.verificationStatus}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
                <div ref={messagesEndRef} />
              </div>

              <div className="p-4 bg-gray-700 border-t border-gray-600">
                {error && (
                  <div className="mb-2 text-red-400 text-sm">{error}</div>
                )}
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                    className="flex-1 px-4 py-2 bg-gray-600 border border-gray-500 rounded text-white focus:ring-2 focus:ring-blue-500"
                    placeholder="Type a message..."
                    disabled={!conversation || connectionStatus !== 'connected'}
                  />
                  <button
                    onClick={sendMessage}
                    disabled={!conversation || connectionStatus !== 'connected'}
                    className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 font-semibold py-2 px-6 rounded transition"
                  >
                    Send
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {showPassphraseModal && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4">
          <div className="bg-gray-800 p-6 rounded-lg max-w-md w-full">
            <h2 className="text-xl font-bold mb-4">Setup Encryption Key</h2>
            <p className="text-sm text-gray-300 mb-4">
              {conversation && conversation.salt ? (
                <>
                  <span className="font-mono">{recipientId}</span> has initiated an encrypted conversation with you.
                  Enter the same passphrase they used to derive the encryption key.
                </>
              ) : (
                <>
                  Enter a passphrase to derive a 256-bit encryption key for this conversation.
                  <span className="font-mono"> {recipientId}</span> will need to enter the same passphrase.
                </>
              )}
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Passphrase
                </label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter shared passphrase"
                  onKeyPress={(e) => e.key === 'Enter' && handleSetupConversation()}
                />
              </div>
              {error && <div className="text-red-400 text-sm">{error}</div>}
              <div className="text-xs text-gray-400">
                <p>• Key derivation: PBKDF2-HMAC-SHA-256</p>
                <p>• Iterations: 200,000</p>
                <p>• Random salt per conversation</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    setShowPassphraseModal(false);
                    setPassphrase('');
                    setError('');
                  }}
                  className="flex-1 bg-gray-600 hover:bg-gray-700 py-2 px-4 rounded transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSetupConversation}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 py-2 px-4 rounded transition"
                >
                  Setup
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
