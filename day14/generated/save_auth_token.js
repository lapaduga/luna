const crypto = require('crypto');

// Хранилище токенов (в реальном приложении - БД)
const tokenStore = new Map();

// Конфигурация
const CONFIG = {
  TOKEN_LENGTH: 64,
  MAX_TOKEN_AGE_MS: 24 * 60 * 60 * 1000, // 24 часа
  CLEANUP_INTERVAL_MS: 60 * 60 * 1000, // 1 час
};

// Очистка просроченных токенов
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of tokenStore.entries()) {
    if (now - data.createdAt > CONFIG.MAX_TOKEN_AGE_MS) {
      tokenStore.delete(token);
    }
  }
}, CONFIG.CLEANUP_INTERVAL_MS);

/**
 * Сохраняет токен авторизации
 * @param {string} token - Токен для сохранения
 * @param {string} userId - ID пользователя
 * @returns {boolean} - Успешность операции
 */
function saveToken(token, userId) {
  if (!token || typeof token !== 'string' || token.length < 10) {
    return false;
  }
  
  if (!userId || typeof userId !== 'string' || userId.length === 0) {
    return false;
  }

  tokenStore.set(token, {
    userId,
    createdAt: Date.now(),
  });

  return true;
}

/**
 * Получает данные токена
 * @param {string} token - Токен для поиска
 * @returns {object|null} - Данные токена или null
 */
function getToken(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const tokenData = tokenStore.get(token);
  
  if (!tokenData) {
    return null;
  }

  // Проверка срока действия
  if (Date.now() - tokenData.createdAt > CONFIG.MAX_TOKEN_AGE_MS) {
    tokenStore.delete(token);
    return null;
  }

  return {
    userId: tokenData.userId,
    createdAt: tokenData.createdAt,
  };
}

/**
 * Удаляет токен
 * @param {string} token - Токен для удаления
 * @returns {boolean} - Успешность операции
 */
function revokeToken(token) {
  if (!token || typeof token !== 'string') {
    return false;
  }

  return tokenStore.delete(token);
}

/**
 * Генерирует новый токен
 * @returns {string} - Сгенерированный токен
 */
function generateToken() {
  return crypto.randomBytes(CONFIG.TOKEN_LENGTH).toString('hex');
}

// Express middleware для обработки токенов
function tokenMiddleware(req, res, next) {
  // Сохранение токена
  if (req.method === 'POST' && req.path === '/auth/token') {
    const { token, userId } = req.body || {};
    
    if (!token || !userId) {
      return res.status(400).json({ error: 'Token and userId are required' });
    }

    if (typeof token !== 'string' || token.length > 1000) {
      return res.status(400).json({ error: 'Invalid token format' });
    }

    if (typeof userId !== 'string' || userId.length > 100) {
      return res.status(400).json({ error: 'Invalid userId format' });
    }

    const saved = saveToken(token, userId);
    
    if (!saved) {
      return res.status(400).json({ error: 'Failed to save token' });
    }

    return res.status(200).json({ success: true });
  }

  // Получение токена
  if (req.method === 'GET' && req.path === '/auth/token') {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization header required' });
    }

    const token = authHeader.substring(7);
    
    if (token.length > 1000) {
      return res.status(400).json({ error: 'Invalid token format' });
    }

    const tokenData = getToken(token);
    
    if (!tokenData) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    return res.status(200).json({
      userId: tokenData.userId,
      createdAt: tokenData.createdAt,
    });
  }

  // Отзыв токена
  if (req.method === 'DELETE' && req.path === '/auth/token') {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization header required' });
    }

    const token = authHeader.substring(7);
    
    if (token.length > 1000) {
      return res.status(400).json({ error: 'Invalid token format' });
    }

    const revoked = revokeToken(token);
    
    if (!revoked) {
      return res.status(404).json({ error: 'Token not found' });
    }

    return res.status(200).json({ success: true });
  }

  next();
}

module.exports = {
  saveToken,
  getToken,
  revokeToken,
  generateToken,
  tokenMiddleware,
};