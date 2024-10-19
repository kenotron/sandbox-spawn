const fs = require("fs");

console.log('inside index.js... waiting...')
setTimeout(() => {
  fs.mkdirSync("hello", { recursive: true });
  fs.appendFileSync("hello/world.txt", "Hello World");
  fs.appendFileSync("hello/2342world.txt", "Hello World");
}, 100);
