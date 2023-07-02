const axios = require('axios');
const cheerio = require('cheerio');
const xss = require('xss');

// URL of the site to test
const url = 'https://www.example.com';

// Function to detect XSS vulnerabilities
async function detectXSS() {
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        let vulnerabilities = [];

        // Search for potentially vulnerable tags to XSS attacks
        $('input, textarea').each((index, element) => {
            const value = $(element).val();
            const sanitizedValue = xss(value);
            if (value !== sanitizedValue) {
                vulnerabilities.push($(element).attr('name'));
            }
        });

        if (vulnerabilities.length > 0) {
            console.log('=== XSS Vulnerabilities ===');
            vulnerabilities.forEach((vulnerability) => {
                console.log(`Detected XSS Vulnerability: ${vulnerability}`);
            });
            console.log();
        } else {
            console.log('No XSS vulnerabilities detected.');
            console.log();
        }
    } catch (error) {
        console.error('Error detecting XSS vulnerabilities:', error);
    }
}

module.exports = detectXSS;
