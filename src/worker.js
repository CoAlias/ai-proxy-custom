import jwt from "@tsndr/cloudflare-worker-jwt";

import { Router, createCors, error, json } from "itty-router";

const { preflight, corsify } = createCors();

const router = Router();

router
  .all("*", preflight)
  .options("*", corsify)
  
  .all("/ai/ping", (request, env, ctx) => {
    return json({
      message: "AI Service is running!"
    });
  })

  .all("/ai/*", async (request, env, ctx) => {
    console.log('Check Client ID');
    
    if(env.CUSTOM_SERVER_NAME) {
      if (!env.CLIENT_ID) return json({ error: "Internal Server Error: No Client ID specified" });
      if (!env.CLIENT_SECRET) return json({ error: "Internal Server Error: No Client SECRET specified" });

      if(request.query.client_id != env.CLIENT_ID) return json({ error: "Unauthorized: Invalid Client ID" });

      request.secret = env.CLIENT_SECRET
    } else {
      var client_id = request.query.client_id;

      if (!client_id) return json({ error: "Unauthorized: No Client ID" });

      var access = await env.CLIENT_KEYS.get(client_id);

      if (!access) return json({ error: "Unauthorized: Invalid Client ID" });

      var access_object = JSON.parse(access);

      request.secret = access_object.secret;

      console.log("Access granted for " + client_id);
    }

    const webtoken = (await request.text()) || request.query.token;

    if (!webtoken) return json({ error: "Request is empty" });

    if (!(await jwt.verify(webtoken, request.secret))) return json({ error: "Unauthorized: Request expired or invalid" });

    if (await isTokenProcessed(webtoken)) return json({ error: "Unauthorized: Request already processed" });

    // Decoding token
    var payload;
      
    try {
      payload = jwt.decode(webtoken).payload;
    } catch(error) {
      return json({ error: "JSON parsing error: " + error.message });
    }

    try {

      function b64_to_utf8(str) {
        return decodeURIComponent(atob(str).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
      }
      var params = (payload.encrypt ? await decrypt(payload.params, request.secret) : b64_to_utf8(payload.params))

      try {
        if (typeof params == "string") params.replace('"', "");

        // check if params is string before parsing
        if (typeof params == "string") params = JSON.parse(params);
        if (typeof params == "string") params = JSON.parse(params);
      } catch(error) {
        return json({ error: "JSON parsing error: " + error.message });
      }

      request.ai_params = params

      var api_key = await decrypt(payload.api_key, request.secret);

      if(!api_key) return json({ error: "API MISSING"});

      request.ai_api_key = api_key

      if(payload.custom_ai_url) request.ai_url = (payload.encrypt ? await decrypt(payload.custom_ai_url, request.secret) : payload.custom_ai_url)
    } catch(e) {
      return json({ error: "Decryption error: " + e.message });
    }
  })

  .all("/ai/openai/*", async (request) => {
    console.log("OpenAI request received!");

    try {
      
      var api_key = request.ai_api_key;

      request.ai_params.stream = true;

      var url = new URL(request.url);

      var endpoint = url.pathname.replace("/ai/openai", "");

      var ai_url = request.ai_url || ("https://api.openai.com" + endpoint)

      console.log(`OpenAI endpoint: ${ai_url}`)

      var response = await fetch(ai_url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${api_key}`,
        },
        body: JSON.stringify(request.ai_params),
      }).catch(function(error){
        return json({ error: "Fetch Error: " + error.message });
      });

      // todo non streaming responses
      if (response.ok) return response;
      else {
        var json_error = await response.json()
        return json({ error: "OpenAI Error: " + json_error?.error?.message, error_object: json_error, error_status_code: response.status, error_type: json_error?.error?.type, error_code: json_error?.error?.code, error_status_text: response.statusText});
      }
    } catch (error) {
      return json({ error: "Invalid Request: " + error.message });
    }
  })

  .all("/ai/openrouter/*", async (request) => {
    console.log("OpenRouter request received!");

    if(!request.query.referer) return json({ error: "No referer passed" });
    if(!request.query.title) return json({ error: "No title passed" });

    try {
      
      var api_key = request.ai_api_key;

      request.ai_params.stream = true;

      var url = new URL(request.url);

      var endpoint = url.pathname.replace("/ai/openrouter", "");

      var ai_url = request.ai_url || ("https://openrouter.ai" + endpoint)

      console.log(`OpenRouter endpoint: ${ai_url}`)

      var response = await fetch(ai_url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "HTTP-Referer": decodeURIComponent(request.query.referer),
          "x-title": request.query.title,
          Authorization: `Bearer ${api_key}`,
        },
        body: JSON.stringify(request.ai_params),
      }).catch(function(error){
        return json({ error: "Fetch Error: " + error.message });
      });

      if (response.ok) return response;
      else {
        var json_text = await response.text();
        console.log(json_text)
        try {
          var json_error = JSON.parse(json_text);
          return json({ error: "OpenRouter Error: " + json_error?.error?.message, error_status_code: response.status, error_status_text: response.statusText});
        } catch(e) {
          return json({ error: "OpenRouter Error: " + json_text, error_status_code: response.status, error_status_text: response.statusText});
        }
      }
    } catch (error) {
      return json({ error: "Invalid Request: " + error.message + error.stack });
    }
  })

  .all("/ai/anthropic/*", async (request) => {
    console.log("Anthropic request received!");

    try {
      
      var api_key = request.ai_api_key;

      request.ai_params.stream = true;

      var url = new URL(request.url);

      var endpoint = url.pathname.replace("/ai/anthropic", "");

      var ai_url = request.ai_url || ("https://api.anthropic.com" + endpoint)

      console.log(`Anthropic endpoint: ${ai_url}`)

      var response = await fetch(ai_url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": api_key,
        },
        body: JSON.stringify(request.ai_params),
      }).catch(function(error){
        return json({ error: "Fetch Error: " + error.message });
      });

      // todo non streaming responses
      if (response.ok) return response;
      else {
        var json_error = await response.json()
        return json({  error: "Anthropic Error: " + json_error?.error?.message, error_type: json_error?.error?.type, error_status_code: response.status, error_status_text: response.statusText});
      }
    } catch (error) {
      return json({ error: "Invalid Request: " + error.message });
    }
  })
  
  .all('*', async (request, env, ctx) => {
    try {
      // Add logic to decide whether to serve an asset or run your original Worker code
      return await getAssetFromKV(
        {
          request,
          waitUntil: ctx.waitUntil.bind(ctx),
        },
        {
          ASSET_NAMESPACE: env.__STATIC_CONTENT,
          ASSET_MANIFEST: assetManifest,
        }
      );
    } catch (e) {
      let pathname = new URL(request.url).pathname;
      return json({ error: "no endpoint found: " + pathname });
    }
  })

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
  var aiproxytoken_cache_key = new Request("https://ai.proxy.com/" + token_hash);

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