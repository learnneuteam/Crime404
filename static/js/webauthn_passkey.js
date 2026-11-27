/* CRIME404 WebAuthn Passkey Enrollment & Authentication */
function b64urlToBuf(value) {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  const raw = atob((value + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0)).buffer;
}

function bufToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function csrfHeaders() {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  return csrf ? { "Content-Type": "application/json", "X-CSRF-Token": csrf } : { "Content-Type": "application/json" };
}

window.enrollProfileBiometric = async function () {
  const statusEl = document.getElementById("prof-bio-msg");
  try {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("This browser does not support WebAuthn passkeys.");
    }
    if (!window.isSecureContext) {
      throw new Error("WebAuthn passkeys require HTTPS or http://localhost:5000.");
    }
    if (statusEl) statusEl.textContent = "Requesting passkey registration options…";
    const optRes = await fetch("/api/webauthn/register/options", { method: "POST", headers: csrfHeaders() });
    const optData = await optRes.json();
    if (!optRes.ok) throw new Error(optData.error || "Unable to start passkey registration.");

    const publicKey = optData.options;
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }

    if (statusEl) statusEl.textContent = "Complete fingerprint, Face ID, Windows Hello, or phone QR passkey prompt…";
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) throw new Error("Passkey creation was cancelled.");

    const label = prompt("Enter a label for this passkey (e.g., Windows Hello Laptop, iPhone Passkey):", "Device / Hybrid Passkey") || "Device / Hybrid Passkey";

    const payload = {
      label,
      credential: {
        id: credential.id,
        rawId: bufToB64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufToB64url(credential.response.attestationObject),
          clientDataJSON: bufToB64url(credential.response.clientDataJSON),
        },
        clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      },
    };

    const verRes = await fetch("/api/webauthn/register/verify", {
      method: "POST",
      headers: csrfHeaders(),
      body: JSON.stringify(payload),
    });
    const verData = await verRes.json();
    if (!verRes.ok) throw new Error(verData.error || "Passkey verification failed.");

    if (statusEl) statusEl.textContent = `✓ Passkey "${label}" registered (${verData.webauthn_count} total).`;
    if (typeof loadUserProfile === "function") await loadUserProfile();
  } catch (err) {
    if (statusEl) statusEl.textContent = `Passkey error: ${err.message}`;
  }
};
