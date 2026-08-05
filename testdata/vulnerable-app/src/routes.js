// Deliberately vulnerable Express handlers.
//
// Every function here exists to trip exactly one bundled Opengrep rule. Do not
// "fix" anything in this file; see ../README.md for the expected findings.
'use strict';

const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

// Trips js-eval-user-input.
function calculate(req, res) {
  const result = eval(req.query.expression);
  res.json({ result });
}

// Also js-eval-user-input, through the Function constructor and a second hop, so
// that two findings of one rule in one file exercise snippet-based identity.
function template(req, res) {
  const source = req.body.template;
  const render = new Function('data', source);
  res.send(render({}));
}

// Trips js-child-process-command-injection.
function convert(req, res) {
  exec('convert ' + req.body.filename + ' /tmp/out.png', (err, stdout) => {
    res.send(stdout);
  });
}

// Trips js-sql-query-from-user-input.
function findUser(req, res, db) {
  db.query('SELECT * FROM users WHERE email = "' + req.query.email + '"', (err, rows) => {
    res.json(rows);
  });
}

// The safe form of the same call, which must NOT be reported. If a scan flags
// this, the sink's focus-metavariable stopped working.
function findUserSafely(req, res, db) {
  db.query('SELECT * FROM users WHERE email = ?', [req.query.email], (err, rows) => {
    res.json(rows);
  });
}

// Trips js-jwt-verify-algorithm-none.
function authenticate(req, res, next) {
  const claims = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, {
    algorithms: ['HS256', 'none'],
  });
  req.user = claims;
  next();
}

module.exports = { calculate, template, convert, findUser, findUserSafely, authenticate };
