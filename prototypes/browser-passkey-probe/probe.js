"use strict";

const enroll = document.querySelector("#enroll");
const assertPasskey = document.querySelector("#assert");
const selection = document.querySelector("#attachment");
const result = document.querySelector("#result");
const rpId = "localhost";
const random = () => crypto.getRandomValues(new Uint8Array(32));
let credentialId;

function report(outcome, text) {
  result.dataset.outcome = outcome;
  result.textContent = text;
}

async function ceremony(name, run) {
  enroll.disabled = true;
  assertPasskey.disabled = true;
  selection.disabled = true;
  report("pending", `${name} requested. Follow the browser prompt.`);
  try {
    await run();
    report("completed", `${name} returned a credential to the page.`);
  } catch (error) {
    // Fixed error names only. Never display or log browser payloads.
    const outcome = ["NotAllowedError", "AbortError", "NotSupportedError", "SecurityError"]
      .includes(error.name) ? error.name : "OtherError";
    report(outcome, `${name} did not complete (${outcome}).`);
  } finally {
    enroll.disabled = false;
    assertPasskey.disabled = !credentialId;
    selection.disabled = false;
  }
}

if (!window.isSecureContext || !window.PublicKeyCredential || location.hostname !== rpId) {
  enroll.disabled = true;
  report("unavailable", "Open the probe through localhost in a browser with WebAuthn.");
} else {
  enroll.addEventListener("click", () => ceremony("Registration", async () => {
    const authenticatorSelection = { residentKey: "required", userVerification: "required" };
    if (selection.value) authenticatorSelection.authenticatorAttachment = selection.value;
    const userId = random();
    const suffix = Array.from(userId.slice(0, 4), byte => byte.toString(16).padStart(2, "0")).join("");
    const credential = await navigator.credentials.create({ publicKey: {
      challenge: random(),
      rp: { id: rpId, name: "SentinelPass disposable probe" },
      user: { id: userId, name: `probe-${suffix}`, displayName: `Test passkey ${suffix}` },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection,
      attestation: "none",
      timeout: 60000,
    } });
    if (!credential || credential.type !== "public-key") throw new Error("Missing credential");
    credentialId = credential.rawId;
  }));

  assertPasskey.addEventListener("click", () => ceremony("Assertion", async () => {
    const credential = await navigator.credentials.get({ publicKey: {
      challenge: random(),
      rpId,
      allowCredentials: [{ id: credentialId, type: "public-key" }],
      userVerification: "required",
      timeout: 60000,
    } });
    if (!credential || credential.type !== "public-key") throw new Error("Missing credential");
    const expected = new Uint8Array(credentialId);
    const actual = new Uint8Array(credential.rawId);
    if (actual.length !== expected.length || actual.some((byte, i) => byte !== expected[i])) {
      throw new Error("Credential did not match");
    }
  }));
}
