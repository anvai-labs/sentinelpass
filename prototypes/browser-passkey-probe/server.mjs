import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const port = Number(process.argv[2] ?? 8765);
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error("Choose a port between 1024 and 65535.");
}
const routes = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/probe.js", ["probe.js", "text/javascript; charset=utf-8"]],
]);
const assets = new Map(await Promise.all([...routes].map(async ([path, [name, type]]) =>
  [path, [await readFile(new URL(name, import.meta.url)), type]]
)));

createServer((request, response) => {
  const headers = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
  };
  const asset = assets.get(request.url);
  if (request.headers.host !== `localhost:${port}` || request.method !== "GET" || !asset) {
    response.writeHead(404, headers).end();
    return;
  }
  response.writeHead(200, { ...headers, "Content-Type": asset[1] }).end(asset[0]);
}).listen(port, "127.0.0.1", () => {
  console.log(`Passkey probe ready at http://localhost:${port}/`);
});
