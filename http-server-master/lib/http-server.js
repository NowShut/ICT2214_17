'use strict';

var fs = require('fs'),
    union = require('union'),
    httpServerCore = require('./core'),
    auth = require('basic-auth'),
    httpProxy = require('http-proxy'),
    corser = require('corser'),
    secureCompare = require('secure-compare');

exports.HttpServer = exports.HTTPServer = HttpServer;

exports.createServer = function (options) {
    return new HttpServer(options);
};

function HttpServer(options) {
    options = options || {};

    if (options.root) {
        this.root = options.root;
    } else {
        try {
            fs.lstatSync('./public');
            this.root = './public';
        } catch (err) {
            this.root = './';
        }
    }

    this.headers = options.headers || {};
    this.headers['Accept-Ranges'] = 'bytes';

    this.cache = options.cache === undefined ? 3600 :
        options.cache === -1 ? 'no-cache, no-store, must-revalidate' : options.cache;

    this.showDir = options.showDir !== 'false';
    this.autoIndex = options.autoIndex !== 'false';
    this.showDotfiles = options.showDotfiles;
    this.gzip = options.gzip === true;
    this.brotli = options.brotli === true;

    if (options.ext) {
        this.ext = options.ext === true ? 'html' : options.ext;
    }

    this.contentType = options.contentType ||
        this.ext === 'html' ? 'text/html' : 'application/octet-stream';

    var before = options.before ? options.before.slice() : [];

    // Implement the checkForMaliciousActivity function here
    before.push(function (req, res) {
        if (checkForMaliciousActivity(req)) {
            // If the request is deemed malicious, redirect to the honeypot
            res.writeHead(302, { 'Location': 'http://127.0.0.1:8080/wp-login' }); // Replace with your actual honeypot URL
            res.end();
        } else {
            res.emit('next');
        }
    });

    if (options.logFn) {
        before.push(function (req, res) {
            options.logFn(req, res);
            res.emit('next');
        });
    }

    if (options.username || options.password) {
        before.push(function (req, res) {
            var credentials = auth(req);
            var usernameEqual = secureCompare(options.username.toString(), credentials.name);
            var passwordEqual = secureCompare(options.password.toString(), credentials.pass);
            if (credentials && usernameEqual && passwordEqual) {
                return res.emit('next');
            }

            res.statusCode = 401;
            res.setHeader('WWW-Authenticate', 'Basic realm=""');
            res.end('Access denied');
        });
    }

    if (options.cors) {
        this.headers['Access-Control-Allow-Origin'] = '*';
        this.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Range';
        if (options.corsHeaders) {
            options.corsHeaders.split(/\s*,\s*/)
                .forEach(function (h) { this.headers['Access-Control-Allow-Headers'] += ', ' + h; }, this);
        }
        before.push(corser.create(options.corsHeaders ? {
            requestHeaders: this.headers['Access-Control-Allow-Headers'].split(/\s*,\s*/)
        } : null));
    }

    if (options.robots) {
        before.push(function (req, res) {
            if (req.url === '/robots.txt') {
                res.setHeader('Content-Type', 'text/plain');
                var robots = options.robots === true
                    ? 'User-agent: *\nDisallow: /'
                    : options.robots.replace(/\\n/, '\n');
                return res.end(robots);
            }
            res.emit('next');
        });
    }

    before.push(httpServerCore({
        root: this.root,
        cache: this.cache,
        showDir: this.showDir,
        showDotfiles: this.showDotfiles,
        autoIndex: this.autoIndex,
        defaultExt: this.ext,
        gzip: this.gzip,
        brotli: this.brotli,
        contentType: this.contentType,
        mimetypes: options.mimetypes,
        handleError: typeof options.proxy !== 'string',
    }));

    if (typeof options.proxy === 'string') {
        var proxy = httpProxy.createProxyServer({});
        before.push(function (req, res) {
            proxy.web(req, res, { target: options.proxy });
        });
    }

    var serverOptions = {
        before: before,
        headers: this.headers,
        onError: function (err, req, res) {
            if (options.logFn) {
                options.logFn(req, res, err);
            }
            res.end();
        }
    };

    if (options.https) {
        serverOptions.https = options.https;
    }

    this.server = union.createServer(serverOptions);

    if (options.timeout !== undefined) {
        this.server.setTimeout(options.timeout);
    }
}

HttpServer.prototype.listen = function () {
    this.server.listen.apply(this.server, arguments);
};

HttpServer.prototype.close = function () {
    return this.server.close();
};



function checkForMaliciousActivity(req) {
    const remoteIP = req.connection.remoteAddress;

    // Check if the IP is in the blocked list
    if (dynamicSecurityMeasures.blockedIPs.includes(remoteIP)) {
        console.log(`Blocked IP ${remoteIP} tried to access`);
        return true;  // Indicate that this is malicious activity
    }
    const userAgent = req.headers['user-agent'];
    const reqPath = req.url.split('?')[0]; // Extract the path without query string
    const queryParams = req.url.split('?')[1]; // Extract the query string
    const method = req.method.toUpperCase();

    // Check for suspicious User-Agent patterns
    if (!userAgent || userAgent.includes('curl') || userAgent.includes('python')) {
        return true;
    }

    // Check for suspicious query parameters
    if (queryParams && (queryParams.includes('test=') || queryParams.includes('sql='))) {
        return true;
    }

    // Check for unusual request paths
    if (reqPath.includes('../') || reqPath.endsWith('.php') || reqPath.endsWith('.asp')) {
        return true;
    }

    // Check for uncommon HTTP methods
    if (['TRACE', 'TRACK'].includes(method)) {
        return true;
    }

    return false;
}
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());

let dynamicSecurityMeasures = {
    blockedIPs: []
};

app.post('/api/predictions', (req, res) => {
    const { attackType, sourceIP } = req.body;
    
    console.log(`Received prediction: ${attackType} from ${sourceIP}`);
    
    // Based on the attack type, update your security measures here directly
    if (sourceIP) {
        // For simplicity, we're just adding the IP to a blocklist
        dynamicSecurityMeasures.blockedIPs.push(sourceIP);
        console.log(`Blocked IP ${sourceIP} based on prediction.`);
        res.status(200).send('Prediction received and security measures updated.');
    } else {
        res.status(400).send('Invalid prediction data.');
    }
});

const port = 4000;
app.listen(port, () => {
    console.log(`Security management server listening at http://localhost:${port}`);
});
