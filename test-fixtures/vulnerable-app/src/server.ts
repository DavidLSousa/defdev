import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';

const app = express();

// VULNERABILITY: CORS with wildcard origin
app.use(cors({ origin: '*' }));

// VULNERABILITY: CORS without configuration
app.use(cors());

// VULNERABILITY: eval() with user input
app.post('/calculate', (req, res) => {
  const { expression } = req.body as { expression: string };
  const result = eval(expression);
  res.json({ result });
});

// VULNERABILITY: Command injection via template literal
app.get('/files', (req, res) => {
  const { dir } = req.query as { dir: string };
  exec(`ls -la ${dir}`, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

// VULNERABILITY: new Function() usage
app.post('/run', (req, res) => {
  const { code } = req.body as { code: string };
  const fn = new Function('return ' + code);
  res.json({ result: fn() });
});

app.listen(3000);
