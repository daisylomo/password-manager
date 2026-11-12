# Password Manager – backend + frontend

Run (Windows PowerShell or Command Prompt, from this folder):

    node server.js

Then open http://localhost:3000

No `npm install` is needed for the app itself (it uses only Node built-ins).

- Backend (`server.js`): HTTP API around the `Keychain` library. Saves the encrypted vault to `vault.json`
  and the SHA-256 checksum to a separate `vault.hash` (stands in for "trusted storage"). On unlock, the
  checksum is passed to `Keychain.load`, so a rolled-back or edited vault is rejected.
- Frontend (`public/index.html`): create/unlock the vault, save, look up and remove passwords, lock.
- Domains are stored only as HMACs, so the UI looks entries up by typing the domain; it cannot list them.
