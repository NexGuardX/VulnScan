const axios = require('axios');
const sqlstring = require('sqlstring');

// URL of the site to test
const url = 'https://www.example.com';

// Function to detect SQL injection vulnerabilities
async function detectSQLInjection() {
    try {
        const payload = `' OR 1=1 --`;
        const encodedPayload = sqlstring.escape(payload);
        const injectionUrl = `${url}/users?username=${encodedPayload}`;
        const response = await axios.get(injectionUrl);

        // Check the response to detect SQL injection
        if (response.data.includes('admin')) {
            console.log('=== SQL Injection Vulnerabilities ===');
            console.log('Detected SQL Injection Vulnerability');
            console.log();
        } else {
            console.log('No SQL injection vulnerabilities detected.');
            console.log();
        }
    } catch (error) {
        console.error('Error detecting SQL injection vulnerabilities:', error);
    }
}

module.exports = detectSQLInjection;
