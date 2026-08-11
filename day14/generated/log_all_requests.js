const express = require('express');

/**
 * Middleware для подробного логирования входящих HTTP-запросов
 * Логирует метод, путь, заголовки и тело запроса
 * Не логирует чувствительные данные (токены, пароли, куки)
 */
function requestLogger(req, res, next) {
  const startTime = Date.now();
  
  // Собираем безопасные заголовки (исключаем чувствительные)
  const safeHeaders = {};
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'x-csrf-token',
    'proxy-authorization'
  ];
  
  for (const [key, value] of Object.entries(req.headers)) {
    if (sensitiveHeaders.includes(key.toLowerCase())) {
      safeHeaders[key] = '[REDACTED]';
    } else {
      safeHeaders[key] = value;
    }
  }
  
  // Логируем тело запроса, если оно есть
  let body = undefined;
  if (req.body && Object.keys(req.body).length > 0) {
    // Создаем копию тела для логирования
    body = JSON.parse(JSON.stringify(req.body));
    
    // Маскируем чувствительные поля в теле
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization', 'api_key', 'apikey'];
    maskSensitiveFields(body, sensitiveFields);
  }
  
  // Основной лог запроса
  console.log('=== INCOMING REQUEST ===');
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`Method: ${req.method}`);
  console.log(`Path: ${req.path}`);
  console.log(`Full URL: ${req.protocol}://${req.get('host')}${req.originalUrl}`);
  console.log(`Headers: ${JSON.stringify(safeHeaders, null, 2)}`);
  
  if (body) {
    console.log(`Body: ${JSON.stringify(body, null, 2)}`);
  } else {
    console.log('Body: (empty or not parsed)');
  }
  
  // Перехватываем завершение ответа для логирования
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const duration = Date.now() - startTime;
    console.log(`Response Status: ${res.statusCode}`);
    console.log(`Response Time: ${duration}ms`);
    console.log('=== END REQUEST ===\n');
    
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
}

/**
 * Рекурсивно маскирует чувствительные поля в объекте
 */
function maskSensitiveFields(obj, sensitiveFields) {
  if (!obj || typeof obj !== 'object') return;
  
  for (const key of Object.keys(obj)) {
    const lowerKey = key.toLowerCase();
    
    if (sensitiveFields.some(field => lowerKey.includes(field))) {
      obj[key] = '[REDACTED]';
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      maskSensitiveFields(obj[key], sensitiveFields);
    }
  }
}

module.exports = requestLogger;