/* ========= Helper Functions ========= */
function log(msg) {
    const pre = document.querySelector("#logArea");
    pre.textContent = `[${new Date().toISOString()}] ${msg}\n` + pre.textContent;
  }
  
  function strToAb(s) { return new TextEncoder().encode(s); }
  function abToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function base64ToAb(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }
  
  /* ========= Elements ========= */
  const genBtn = document.getElementById("genBtn");
  const importBtn = document.getElementById("importBtn");
  const exportPubBtn = document.getElementById("exportPubBtn");
  const exportPrivBtn = document.getElementById("exportPrivBtn");
  const signBtn = document.getElementById("signBtn");
  const verifyBtn = document.getElementById("verifyBtn");
  const makeExampleBtn = document.getElementById("makeExampleBtn");
  const verifyExternalBtn = document.getElementById("verifyExternalBtn");
  
  const messageInput = document.getElementById("messageInput");
  const wrappedJsonOut = document.getElementById("wrappedJsonOut");
  const signatureOut = document.getElementById("signatureOut");
  const pubJwkOut = document.getElementById("pubJwkOut");
  const privJwkOut = document.getElementById("privJwkOut");
  const signedPackageOut = document.getElementById("signedPackageOut");
  
  /* ========= Cryptographic State ========= */
  let keyPair = null;
  let exportedPublicJwk = null;
  let exportedPrivateJwk = null;
  let lastWrappedJson = null;
  let lastSignature = null;
  
  /* ========= Generate Key Pair ========= */
  genBtn.onclick = async () => {
    try {
      log("Generating key pair...");
      keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
  
      exportedPublicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      exportedPrivateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  
      pubJwkOut.textContent = JSON.stringify(exportedPublicJwk, null, 2);
      privJwkOut.textContent = JSON.stringify(exportedPrivateJwk, null, 2);
  
      signBtn.disabled = false;
      verifyBtn.disabled = false;
      exportPubBtn.disabled = false;
      exportPrivBtn.disabled = false;
  
      log("Key pair created.");
    } catch (e) {
      log("Error generating key: " + e.message);
    }
  };
  
  /* ========= Import Private JWK ========= */
  importBtn.onclick = async () => {
    try {
      const raw = prompt("Paste private JWK:");
      if (!raw) return;
      const jwk = JSON.parse(raw);
  
      const priv = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      );
  
      exportedPrivateJwk = jwk;
      keyPair = { privateKey: priv, publicKey: null };
  
      // Derive public JWK if exists
      exportedPublicJwk =
        jwk.x && jwk.y
          ? { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true }
          : null;
  
      pubJwkOut.textContent =
        exportedPublicJwk ? JSON.stringify(exportedPublicJwk, null, 2) : "—";
      privJwkOut.textContent = JSON.stringify(jwk, null, 2);
  
      signBtn.disabled = false;
      exportPrivBtn.disabled = false;
      verifyBtn.disabled = !exportedPublicJwk;
  
      log("Private key imported.");
    } catch (e) {
      log("Import failed: " + e.message);
    }
  };
  
  /* ========= Export Keys ========= */
  exportPubBtn.onclick = () => {
    const blob = new Blob([JSON.stringify(exportedPublicJwk, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "public-key.jwk.json";
    a.click();
    URL.revokeObjectURL(url);
  };
  
  exportPrivBtn.onclick = () => {
    const blob = new Blob([JSON.stringify(exportedPrivateJwk, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "private-key.jwk.json";
    a.click();
    URL.revokeObjectURL(url);
  };
  
  /* ========= Sign Message ========= */
  signBtn.onclick = async () => {
    const msg = messageInput.value.trim();
    if (!msg) return log("Message empty.");
  
    const wrapped = {
      message: msg,
      timestamp: new Date().toISOString(),
    };
  
    lastWrappedJson = JSON.stringify(wrapped);
    wrappedJsonOut.textContent = lastWrappedJson;
  
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      keyPair.privateKey,
      strToAb(lastWrappedJson)
    );
  
    lastSignature = abToBase64(signature);
    signatureOut.textContent = lastSignature;
    log("Message signed.");
  };
  
  /* ========= Local Verify ========= */
  verifyBtn.onclick = async () => {
    if (!exportedPublicJwk) return log("No public key.");
  
    const pubKey = await crypto.subtle.importKey(
      "jwk",
      exportedPublicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
  
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      pubKey,
      base64ToAb(lastSignature),
      strToAb(lastWrappedJson)
    );
  
    log(ok ? "Verification SUCCESS" : "Verification FAILED");
  };
  
  /* ========= Make Example Package ========= */
  makeExampleBtn.onclick = () => {
    const pkg = {
      message: JSON.parse(lastWrappedJson),
      signature: lastSignature,
      publicKeyJwk: exportedPublicJwk,
      algorithm: "ECDSA-P256-SHA256",
    };
  
    signedPackageOut.textContent = JSON.stringify(pkg, null, 2);
    window.__SIGNED_PACKAGE_EXAMPLE = pkg;
  
    log("Example package created.");
  };
  
  /* ========= External Verifier (Signature-First) ========= */
  verifyExternalBtn.onclick = () => {
    const html = `
  <!doctype html>
  <html>
  <head>
  <meta charset="utf-8">
  <title>ECDSA Verifier</title>
  <style>
  body{background:#0f1724;color:#e6eef8;font-family:Inter;padding:25px}
  .card{max-width:700px;margin:auto;background:#111827;padding:20px;border-radius:12px}
  textarea{width:100%;padding:10px;background:#1a2333;color:white;border-radius:8px;border:1px solid #333;font-family:monospace;margin-bottom:12px}
  button{padding:8px 12px;border-radius:8px;border:none;background:#7c3aed;color:white;margin-right:8px;font-weight:600;cursor:pointer}
  .secondary{background:transparent;border:1px solid #555;color:#aaa}
  .output{background:#0d1525;padding:12px;border-radius:8px;margin-top:10px;min-height:80px}
  </style>
  </head>
  <body>
  
  <div class="card">
  <h2>External Signature Verifier</h2>
  
  <label>Signature (Base64)</label>
  <textarea id="sigArea" rows="2"></textarea>
  
  <label>Public Key (JWK)</label>
  <textarea id="pubArea" rows="4"></textarea>
  
  <label>Message JSON</label>
  <textarea id="msgArea" rows="6"></textarea>
  
  <button id="verifyBtn">Verify</button>
  <button id="loadSample" class="secondary">Load Example</button>
  
  <div class="output"><pre id="result">—</pre></div>
  </div>
  
  <script>
  function base64ToAb(b64){
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }
  
  const sigArea = document.getElementById("sigArea");
  const pubArea = document.getElementById("pubArea");
  const msgArea = document.getElementById("msgArea");
  const verifyBtn = document.getElementById("verifyBtn");
  const loadSample = document.getElementById("loadSample");
  const result = document.getElementById("result");
  
  loadSample.onclick = () => {
    try{
      const pkg = window.opener.__SIGNED_PACKAGE_EXAMPLE;
      sigArea.value = pkg.signature;
      pubArea.value = JSON.stringify(pkg.publicKeyJwk,null,2);
      msgArea.value = JSON.stringify(pkg.message,null,2);
    }catch(e){
      alert("No sample available.");
    }
  };
  
  verifyBtn.onclick = async () => {
    try{
      result.textContent = "Working...";
  
      const signature = sigArea.value.trim();
      const pubJwk = JSON.parse(pubArea.value.trim());
      const message = JSON.parse(msgArea.value.trim());
  
      const pubKey = await crypto.subtle.importKey(
        "jwk",
        pubJwk,
        {name:"ECDSA", namedCurve:"P-256"},
        true,
        ["verify"]
      );
  
      const valid = await crypto.subtle.verify(
        {name:"ECDSA", hash:{name:"SHA-256"}},
        pubKey,
        base64ToAb(signature),
        new TextEncoder().encode(JSON.stringify(message))
      );
  
      result.textContent = valid ? "VERIFIED ✔️" : "INVALID ❌";
    }catch(e){
      result.textContent = "ERROR: " + e.message;
    }
  };
  </script>
  </body>
  </html>`;
  
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
  };
  