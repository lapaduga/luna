const https = require('https');

/**
 * Fetch user data from external API by user ID
 * @param {string} userId - The user ID to fetch
 * @returns {Promise<object>} - User data object
 */
async function fetchUserById(userId) {
    // Validate input
    if (!userId || typeof userId !== 'string' || userId.length > 100) {
        throw new Error('Invalid user ID provided');
    }

    const apiUrl = process.env.USER_API_URL || 'https://jsonplaceholder.typicode.com';
    const apiKey = process.env.USER_API_KEY;

    if (!apiKey) {
        throw new Error('API key not configured');
    }

    const url = new URL(`${apiUrl}/users/${encodeURIComponent(userId)}`);

    const options = {
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Accept': 'application/json',
            'User-Agent': 'NodeJS-UserService/1.0'
        },
        timeout: 5000
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            let data = '';

            if (res.statusCode < 200 || res.statusCode >= 300) {
                reject(new Error(`External API returned status ${res.statusCode}`));
                return;
            }

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve(parsed);
                } catch (err) {
                    reject(new Error('Failed to parse API response'));
                }
            });
        });

        req.on('error', (err) => {
            reject(new Error(`Request failed: ${err.message}`));
        });

        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timed out'));
        });

        req.end();
    });
}

module.exports = { fetchUserById };