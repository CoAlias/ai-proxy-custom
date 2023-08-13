import jwt from "@tsndr/cloudflare-worker-jwt";

import { Router, createCors, error, json } from "itty-router";

const { preflight, corsify } = createCors();

const router = Router();

router
  .all("*", preflight)
  .options("*", corsify)
  .all("*", async (request, env, ctx) => {
    if (!env.CLIENT_ID) return json({ error: "Internal Server Error: No Client ID specified" });
    if (!env.CLIENT_SECRET) return json({ error: "Internal Server Error: No Client SECRET specified" });

    console.log('Check Client ID');

    var client_id = request.query.client_id;

    if (!client_id) return json({ error: "Unauthorized: No Client ID" });

    if (client_id != env.CLIENT_ID) return json({ error: "Unauthorized: Invalid Client ID" });

    console.log("Access granted for " + client_id);
  })

  .all("/openai/*", async (request, env, ctx) => {
    console.log("OpenAI request received!");

    const webtoken = (await request.text()) || request.query.token;

    if (!webtoken) return json({ error: "Request is empty" });

    if (!(await jwt.verify(webtoken, env.CLIENT_SECRET))) return json({ error: "Unauthorized: Request expired or invalid" });

    if (await isTokenProcessed(webtoken)) return json({ error: "Unauthorized: Request already processed" });

    try {
      // Decoding token
      var payload;
      
      try {
        payload = jwt.decode(webtoken).payload;
      } catch(error) {
        return json({ error: "JSON parsing error: " + error.message });
      }

      var params = atob(payload.params);

      console.log(payload.api_key)

      var api_key = await decrypt(payload.api_key, env.CLIENT_SECRET);

      if(!api_key) return json({ error: "API MISSING"});

      try {
        if (typeof params == "string") params.replace('"', "");

        // check if params is string before parsing
        if (typeof params == "string") params = JSON.parse(params);
        if (typeof params == "string") params = JSON.parse(params);
      } catch(error) {
        return json({ error: "JSON parsing error: " + error.message });
      }

      params.stream = true;

      var url = new URL(request.url);

      var endpoint = url.pathname.replace("/openai", "");

      var ai_url = payload.custom_ai_url || ("https://api.openai.com" + endpoint)

      console.log(`OpenAI endpoint: ${ai_url}`)

      var response = await fetch(ai_url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${api_key}`,
        },
        body: JSON.stringify(params),
      }).catch(function(error){
        return json({ error: "Fetch Error: " + error.message });
      });

      if (response.ok) return response;
      else return json({ error: "OpenAI Error: " + (await response.json())?.error?.message });
    } catch (error) {
      return json({ error: "Invalid Request: " + error.message });
    }
  })

  .all("*", () => {
    return json({ error: "no endpoint found" });
  });

// Example: Cloudflare Worker module syntax
export default {
  fetch: (request, ...args) =>
    router
      .handle(request, ...args)
      .catch((err) => error(500, err.stack))
      .then(corsify), // send as JSON
};

async function isTokenProcessed(webtoken) {
  var aiproxytoken_cache = await caches.open("ai-proxy-webtoken");
  
  // ComputeHash function embedded
  async function computeHash(token) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const token_hash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    return token_hash;
  }

  var token_hash = await computeHash(webtoken);
  var aiproxytoken_cache_key = new Request("https://nocodesaastoolbox.com//" + token_hash);

  if (await aiproxytoken_cache.match(aiproxytoken_cache_key)) return true;
  else {
    await aiproxytoken_cache.put(aiproxytoken_cache_key, new Response("done"));
    return false;
  }
}

async function decrypt(text, password) {
  const KEY_LENGTH = 32; // AES-256
  const IV_LENGTH = 12;  // GCM standard
  const AUTH_TAG_LENGTH = 16; // AES-GCM auth tag

  const rawData = atob(text);  // Base64 decode
  const data = new Uint8Array([...rawData].map(char => char.charCodeAt(0)));

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 16 + IV_LENGTH);
  const authTag = data.slice(16 + IV_LENGTH, 16 + IV_LENGTH + AUTH_TAG_LENGTH);
  const encryptedText = data.slice(16 + IV_LENGTH + AUTH_TAG_LENGTH);

  const combinedEncryptedText = new Uint8Array(encryptedText.length + AUTH_TAG_LENGTH);
  combinedEncryptedText.set(encryptedText);
  combinedEncryptedText.set(authTag, encryptedText.length);

  const cryptoKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
      {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256',
      },
      cryptoKey,
      { name: 'AES-GCM', length: KEY_LENGTH * 8 },
      true,
      ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
      {
          name: 'AES-GCM',
          iv: iv,
          additionalData: new Uint8Array(0),
          tagLength: 128,
      },
      key,
      combinedEncryptedText
  );

  return new TextDecoder().decode(decrypted);
}