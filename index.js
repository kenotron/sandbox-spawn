const fs = require("fs");

setTimeout(() => {
  fs.mkdirSync("hello", { recursive: true });
  fs.appendFileSync("hello/world.txt", "Hello World");
  fs.appendFileSync("hello/2342world.txt", "Hello World");
}, 2000);
