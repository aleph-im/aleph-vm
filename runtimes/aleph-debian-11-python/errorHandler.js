const fs = require('fs');
const http = require('http');
const path = require('path');
const process = require('process');

process.chdir('/root');

const port = 8881;
const directoryName = './error';

const types = {
  html: 'text/html',
  css: 'text/css',
  js: 'application/javascript',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  json: 'application/json',
  xml: 'application/xml',
};

const root = path.normalize(path.resolve(directoryName));

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);

  const extension = path.extname(req.url).slice(1);
  const type = extension ? types[extension] : types.html;
  const supportedExtension = Boolean(type);

  if (!supportedExtension) {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('404: File not found');
    return;
  }

  let fileName = req.url;
  if (req.url === '/') fileName = 'index.html';
  else if (!extension) {
    try {
      fs.accessSync(path.join(root, req.url + '.html'), fs.constants.F_OK);
      fileName = req.url + '.html';
    } catch (e) {
      fileName = path.join(req.url, 'index.html');
    }
  }

  const filePath = path.join(root, fileName);
  const isPathUnderRoot = path
      .normalize(path.resolve(filePath))
      .startsWith(root);

  if (!isPathUnderRoot) {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('404: File not found');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('404: File not found');
    } else {
      let statusCode = 200
      if (filePath === '/root/error/index.html') {
        statusCode = 503
      }
      res.writeHead(statusCode, { 'Content-Type': type });
      res.end(data);
    }
  });
});

server.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
