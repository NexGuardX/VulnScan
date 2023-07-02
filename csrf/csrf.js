const axios = require('axios');
const tough = require('tough-cookie');

// URL of the site to test
const url = 'https://www.example.com';

// Function to detect CSRF vulnerabilities
async function detectCSRF() {
    try {
        const csrfCookie = new tough.Cookie({
            key: 'csrfToken',
            value: 'random_token_value',
            domain: 'example.com',
            httpOnly: true,
            secure: true
        });

        const response = await axios.post(`${url}/update-password`, { password: 'new_password' }, {
            headers: { 'X-CSRF-Token': 'random_token_value' },
            withCredentials: true,
            jar: tough.CookieJar().setCookie(csrfCookie, url)
        });

        // Check the response to detect CSRF vulnerability
        if (response.data.includes('Password updated successfully')) {
            console.log('=== CSRF Vulnerabilities ===');
            console.log('Detected CSRF Vulnerability');
            console.log();
        } else {
            console.log('No CSRF vulnerabilities detected.');
            console.log();
        }
    } catch (error) {
        console.error('Error detecting CSRF vulnerabilities:', error);
    }
}

module.exports = detectCSRF;
