const axios = require("axios");
const cheerio = require("cheerio");
const xss = require("xss");
const xpath = require("xpath");
const xmldom = require("xmldom");
const sqlstring = require("sqlstring");
const tough = require("tough-cookie");

// URL of the site to test
const url = "https://www.example.com";

// Function to detect XSS vulnerabilities
async function detectXSS() {
  try {
    const response = await axios.get(url);
    const $ = cheerio.load(response.data);

    let vulnerabilities = [];

    // Search for potentially vulnerable input fields and text areas
    $("input, textarea").each((index, element) => {
      const value = $(element).val();
      const sanitizedValue = xss(value);
      if (value !== sanitizedValue) {
        vulnerabilities.push(
          `Detected XSS Vulnerability: ${$(element).attr("name")}`
        );
      }
    });

    if (vulnerabilities.length > 0) {
      console.log("=== XSS Vulnerabilities ===");
      vulnerabilities.forEach((vulnerability) => {
        console.log(vulnerability);
      });
    } else {
      console.log("No XSS vulnerabilities detected.");
    }
  } catch (error) {
    console.error("Error detecting XSS vulnerabilities:", error);
  }
}

// Function to detect XEE vulnerabilities
async function detectXEE() {
  try {
    const response = await axios.get(url);
    const doc = new xmldom.DOMParser().parseFromString(response.data);

    // Use XPath to search for potentially vulnerable external entities
    const nodes = xpath.select("//parsererror", doc);
    if (nodes.length > 0) {
      console.log("=== XEE Vulnerabilities ===");
      console.log("Detected XEE Vulnerability");
    } else {
      console.log("No XEE vulnerabilities detected.");
    }
  } catch (error) {
    console.error("Error detecting XEE vulnerabilities:", error);
  }
}

// Function to detect SQL injection vulnerabilities
async function detectSQLInjection() {
  try {
    const payload = `' OR 1=1 --`;
    const encodedPayload = sqlstring.escape(payload);
    const injectionUrl = `${url}/users?username=${encodedPayload}`;
    const response = await axios.get(injectionUrl);

    // Check the response to detect SQL injection
    if (response.data.includes("admin")) {
      console.log("=== SQL Injection Vulnerabilities ===");
      console.log("Detected SQL Injection Vulnerability");
    } else {
      console.log("No SQL injection vulnerabilities detected.");
    }
  } catch (error) {
    console.error("Error detecting SQL injection vulnerabilities:", error);
  }
}

// Function to detect CSRF vulnerabilities
async function detectCSRF() {
  try {
    // Use a valid CSRF cookie
    const csrfCookie = new tough.Cookie({
      key: "csrf_token",
      value: "random_token_value",
      domain: "example.com",
      httpOnly: true,
      secure: true,
    });

    const cookieJar = new tough.CookieJar();
    cookieJar.setCookie(csrfCookie, url);

    const response = await axios.post(
      `${url}/update-password`,
      { password: "new_password" },
      {
        headers: { "X-CSRF-Token": "random_token_value" },
        withCredentials: true,
        jar: cookieJar,
      }
    );

    // Check the response to detect CSRF vulnerability
    if (response.data.includes("Password updated successfully")) {
      console.log("=== CSRF Vulnerabilities ===");
      console.log("Detected CSRF Vulnerability");
    } else {
      console.log("No CSRF vulnerabilities detected.");
    }
  } catch (error) {
    console.error("Error detecting CSRF vulnerabilities:", error);
  }
}

// Execute the vulnerability detection
detectXSS();
detectXEE();
detectSQLInjection();
detectCSRF();
