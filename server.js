'use strict';
const https = require('https');
const fs = require('fs');
const express = require('express');
const Session = require('express-session');
const request = require('request');
const randomstring = require('randomstring');
require('request-debug')(request);

let config;
try {
  config = require('./config-override.json');
} catch (e) {
  config = config || require('./config.json');
}

const REDIRECT_URI = `${config.app.host}:${config.app.port}/oauthCallback`;
const SCOPE = 'https://conceptboard.com/ns/oauth#scope-board.meta,https://conceptboard.com/ns/oauth#scope-board.meta.write';

const app = express();
app.use(Session({
  secret: 'secret-circuit-is-great',
  resave: true,
  saveUninitialized: true
}));

function auth(req, res, next) {
  req.session.isAuthenticated ? next() : res.redirect('/');
}

app.get('/myboards', auth, (req, res) => {
  request.get(`${config.conceptboard.domain}/users/me/boards`, {
    auth: {
      bearer: req.session.access_token
    }
  }, (err, httpResponse, body) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(body);
  });
});

app.get('/createboard', auth, (req, res) => {
  const name = `api-test ${randomstring.generate(6)}`;
  request.post({
    url: `${config.conceptboard.domain}/users/me/boards`,
    auth: { bearer: req.session.access_token },
    gzip: true,
    json: { title: name }
  }, (err, httpResponse, body) => {
    res.send(err || body || `${httpResponse.statusCode}:${httpResponse.statusMessage}`);
  });
});

app.get('/logout', (req, res) => {
  req.session.isAuthenticated = false;
  req.session.access_token = null;
  res.redirect('/');
});

app.use('/oauthCallback', (req, res) => {
  if (req.query.code && req.session.oauthState === req.query.state) {
    request.post({
      url: `${config.conceptboard.domain}${config.conceptboard.token_url}`,
      auth: {
        user: config.conceptboard.client_id,
        password: config.conceptboard.client_secret
      },
      form: {
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code',
        code: req.query.code
      }
    }, (err, httpResponse, body) => {
      if (!err && body) {
        req.session.access_token = JSON.parse(body).access_token;
        req.session.isAuthenticated = true;
        res.redirect('/');
      } else {
        res.send(401);
      }
    });
  } else {
    // Access denied
    res.redirect('/');
  }
});

app.get('/', (req, res) => {
  if (req.session.isAuthenticated) {
    res.send(`
      <a href='/myboards'>List my boards</a><br>
      <a href='/createboard'>Create new board</a><br>
      <a href='/logout'>Logout</a>
    `);
  } else {
    let redirectUri = encodeURIComponent(REDIRECT_URI);
    let scope = encodeURIComponent(SCOPE);
    let state = randomstring.generate(12);
    let url = `${config.conceptboard.domain}${config.conceptboard.authorize_url}?scope=${scope}&state=${state}&redirect_uri=${redirectUri}&response_type=code&client_id=${config.conceptboard.client_id}`;
    // Save state in session and check later to prevent CSRF attacks
    req.session.oauthState = state;
    res.send(`<a href=${url}>Login to Conceptboard</a>`);
  }
});

const server = https.createServer({
  key: fs.readFileSync(config.app.key),
  cert: fs.readFileSync(config.app.cert)
}, app);
server.listen(config.app.port);

server.on('listening', () => console.log(`listening on ${config.app.port}`));