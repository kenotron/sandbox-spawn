const fs = require("fs");

fs.mkdirSync("hello", { recursive: true });
fs.appendFileSync("hello/not-related.txt", "Hello World");
