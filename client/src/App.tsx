import { useState, useEffect } from 'react';
import { WebSocketClient } from './lib/websocket';
import { Message, WSMessage, Conversation } from './types';
import {
  generateSalt,
  deriveKeyBytes,
  verifyHash,
  createCanonicalAAD,
  saltToBase64,
  base64ToSalt,
  AVAILABLE_CIPHERS,
  encryptWithCipher,
  decryptWithCipher,
  type CipherType,
} from './lib/crypto';
import './index.css';

const WS_URL = 'ws://localhost:8080/ws';

function App() {
  const [wsClient] = useState(() => new WebSocketClient(WS_URL));
  const [connected, setConnected] = useState(false);
  const [userId, setUserId] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [selectedCipher, setSelectedCipher] = useState<CipherType>('AES-256-CBC');
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [error, setError] = useState('');
  const [showLogin, setShowLogin] = useState(true);

  // Log when component mounts/unmounts
  useEffect(() => {
    console.log('App component mounted');
    return () => {
      console.log('App component unmounting');
    };
  }, []);

  // Log conversation state changes
  useEffect(() => {
    console.log('Conversation state changed:', conversation ? {
      userId: conversation.userId,
      counter: conversation.counter,
      hasKey: !!conversation.encryptionKey,
      cipher: conversation.selectedCipher
    } : 'NULL');
  }, [conversation]);

  useEffect(() => {
    const connectHandler = () => {
      setConnected(true);
      setError('');
    };

    const disconnectHandler = () => {
      setConnected(false);
    };

    wsClient.onConnect(connectHandler);
    wsClient.onDisconnect(disconnectHandler);

    return () => {
      wsClient.disconnect();
    };
  }, [wsClient]);

  // Separate useEffect for message handling with conversation dependency
  useEffect(() => {
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

    // Register handler and get cleanup function
    const unsubscribe = wsClient.onMessage(handleIncomingMessage);
    
    // Cleanup: remove this specific handler when conversation changes or component unmounts
    return unsubscribe;
  }, [wsClient, conversation]);

  const handleReceivedMessage = async (msg: WSMessage) => {
    console.log('Received message:', msg);
    console.log('Current conversation state:', conversation);
    
    if (!conversation || !conversation.encryptionKey) {
      console.error('Decryption failed - conversation:', conversation);
      setError('Cannot decrypt: encryption key not set. Please complete encryption setup first.');
      return;
    }

    try {
      const aad = createCanonicalAAD({
        senderId: msg.senderId!,
        recipientId: msg.recipientId!,
        counter: msg.counter!,
      });

      // Decrypt using the cipher specified in the message
      const encrypted = {
        iv: msg.iv!,
        ciphertext: msg.ciphertext!,
        authTag: msg.authTag || '',
        sha256: msg.sha256_plaintext!,
      };

      console.log('Attempting to decrypt with cipher:', msg.cipher);
      console.log('Encryption key type:', typeof conversation.encryptionKey);

      const plaintext = await decryptWithCipher(
        encrypted,
        conversation.encryptionKey,
        msg.cipher! as CipherType,
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
      // For XOR and Caesar ciphers, use the passphrase directly as a string key
      // For AES-256-CBC, derive a Uint8Array key
      let encryptionKey: CryptoKey | Uint8Array | string;
      let salt: Uint8Array | undefined;

      console.log('Setting up encryption with cipher:', selectedCipher);

      if (selectedCipher === 'AES-256-CBC') {
        // Check if salt exists in localStorage
        const conversationId = [userId, recipientId].sort().join('_');
        const savedSalt = localStorage.getItem(`salt_${conversationId}`);

        if (savedSalt) {
          salt = base64ToSalt(savedSalt);
          console.log('Using existing salt');
        } else {
          salt = await generateSalt();
          localStorage.setItem(`salt_${conversationId}`, saltToBase64(salt));
          console.log('Generated new salt');
        }

        console.log('Deriving encryption key (Uint8Array)...');
        encryptionKey = await deriveKeyBytes(passphrase, salt);
        console.log('Key derived successfully, type:', typeof encryptionKey);
      } else {
        // For XOR and Caesar, use passphrase as string key
        encryptionKey = passphrase;
        console.log('Using passphrase as string key');
      }

      const newConversation = {
        userId: userId,
        counter: 0,
        encryptionKey,
        salt,
        selectedCipher,
      };

      console.log('Setting conversation state:', { 
        ...newConversation, 
        encryptionKey: encryptionKey ? 'SET' : 'NULL' 
      });

      setConversation(newConversation);

      // Persist critical conversation data to localStorage (except CryptoKey/Uint8Array which can't be serialized easily)
      if (selectedCipher !== 'AES-256-CBC') {
        // For XOR/Caesar, we can store the string key
        localStorage.setItem('conversation', JSON.stringify(newConversation));
      } else {
        // For AES, store everything except the CryptoKey
        localStorage.setItem('conversation_metadata', JSON.stringify({
          userId: recipientId,
          counter: 0,
          selectedCipher,
          hasSalt: !!salt
        }));
      }

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
      const cipherToUse = (conversation.selectedCipher as CipherType) || 'AES-256-CBC';

      const aad = createCanonicalAAD({
        senderId: userId,
        recipientId: recipientId,
        counter: newCounter,
      });

      const encrypted = await encryptWithCipher(
        inputMessage,
        conversation.encryptionKey,
        cipherToUse,
        aad
      );

      const message: WSMessage = {
        type: 'MSG',
        senderId: userId,
        recipientId: recipientId,
        counter: newCounter,
        timestamp: Math.floor(Date.now() / 1000),
        cipher: cipherToUse,
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
        cipher: 'AES-256-CBC',
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
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Encryption Method
              </label>
              <select
                value={selectedCipher}
                onChange={(e) => setSelectedCipher(e.target.value as CipherType)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {AVAILABLE_CIPHERS.map((cipher) => (
                  <option key={cipher.name} value={cipher.name}>
                    {cipher.name} - Security: {cipher.securityLevel.toUpperCase()}
                  </option>
                ))}
              </select>
              {/* Security level indicator */}
              {(() => {
                const currentCipher = AVAILABLE_CIPHERS.find(c => c.name === selectedCipher);
                if (!currentCipher) return null;
                return (
                  <div className={`mt-2 p-3 rounded-lg flex items-center gap-2 ${
                    currentCipher.color === 'red' ? 'bg-red-50 border border-red-200' :
                    currentCipher.color === 'orange' ? 'bg-orange-50 border border-orange-200' :
                    'bg-green-50 border border-green-200'
                  }`}>
                    <span className={`inline-block w-3 h-3 rounded-full ${
                      currentCipher.color === 'red' ? 'bg-red-500' :
                      currentCipher.color === 'orange' ? 'bg-orange-500' :
                      'bg-green-500'
                    }`}></span>
                    <span className={`text-sm font-medium ${
                      currentCipher.color === 'red' ? 'text-red-700' :
                      currentCipher.color === 'orange' ? 'text-orange-700' :
                      'text-green-700'
                    }`}>
                      {currentCipher.securityLevel === 'high' 
                        ? '🔒 High Security - Recommended for production'
                        : currentCipher.securityLevel === 'medium'
                        ? '⚠️ Medium Security - Use with caution'
                        : '⚠️ Low Security - Educational purposes only'}
                    </span>
                  </div>
                );
              })()}
            </div>
            <div className="text-xs text-gray-600 bg-yellow-50 p-3 rounded">
              ⚠️ Both users must use the same passphrase AND encryption method. Share them securely out-of-band.
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
