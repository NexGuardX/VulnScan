const axios = require('axios');
const xpath = require('xpath');
const xmldom = require('xmldom');

// URL of the site to test
const url = 'https://www.example.com';

// Function to detect XEE vulnerabilities
async function detectXEE() {
    try {
        const response = await axios.get(url);
        const doc = new xmldom.DOMParser().parseFromString(response.data);

        // Use XPath to search for potentially vulnerable external entities
        const nodes = xpath.select('//parsererror', doc);
        if (nodes.length > 0) {
            console.log('=== XEE Vulnerabilities ===');
            console.log('Detected XEE Vulnerability');
            console.log();
        } else {
            console.log('No XEE vulnerabilities detected.');
            console.log();
        }
    } catch (error) {
        console.error('Error detecting XEE vulnerabilities:', error);
    }
}

module.exports = detectXEE;
