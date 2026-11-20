# Cross-platform browser passkey probe

Run on the desktop you want to qualify, with Node.js and a headed browser:

```sh
node prototypes/browser-passkey-probe/server.mjs
```

Open http://localhost:8765/ in a disposable browser profile on that same
machine. The server binds to IPv4 loopback and accepts only the localhost host
and static GET requests. Supply a different port as the first argument if needed.

1. Select Platform to exercise Windows Hello in Edge or Chrome. Select
   Cross-platform security key to exercise a physical FIDO2 USB key in those
   browsers or in Chrome and Firefox on Ubuntu. Use Browser chooser to inspect
   an available plugin or browser provider.
2. Click **Enroll test passkey**. Complete the prompt with the intended
   authenticator. Record the provider selected and the fixed page outcome.
3. Click **Use enrolled passkey** on the same page. Complete the next prompt.
   Record the result and report which user verification method was used.
4. Repeat a ceremony and cancel the native prompt. With a test security key,
   also check the browser's response when you disconnect it during a ceremony.
5. Remove the test passkey through the authenticator's management UI. Close
   the page and stop the server. Use only a disposable credential and verify
   its label before removing it.

The page keeps the registered credential ID in memory until reload. It sends
no credential material to the server and displays only fixed outcome messages.
A successful assertion matches the earlier credential ID at the page. The
probe does not verify signatures or grant access. Use the disposable Identity
journey to demonstrate actual server acceptance on each claimed combination.

Capture the OS, browser and package versions, provider selected, ceremony
outcomes, and whether verification used hardware or a PIN. Browser return
alone cannot identify the authenticator. For a cancel-only provider probe,
confirm callback delivery via its fixed marker and record the cancellation
as expected. A browser or system may restrict provider routing for localhost.
If it does, record that limitation and use an authorized disposable HTTPS RP
for the provider routing check.

Development validation used a Chromium virtual CTAP2 USB authenticator on
macOS. The smoke run completed registration and assertion, verified the page
clears its in-memory credential state on reload, and checked that the server
rejects POST and alternate Host requests. Windows and Ubuntu hardware and
provider outcomes remain pending.
