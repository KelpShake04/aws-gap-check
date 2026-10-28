// Cognito Hosted UI 로그인 (Authorization Code + PKCE). 토큰은 sessionStorage에만 둔다(탭을 닫으면 사라짐).
const TOKENS = "agc.tokens";
const PENDING = "agc.pkce";

export function base64url(bytes) {
  let text = "";
  for (const byte of new Uint8Array(bytes)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(digest);
}

function randomString(bytes) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function login(config) {
  const verifier = randomString(48);
  const state = randomString(16);
  sessionStorage.setItem(PENDING, JSON.stringify({ verifier, state }));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: "openid email",
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: "S256",
  });
  location.assign(`${config.cognitoDomain}/oauth2/authorize?${params}`);
}

// 로그인 후 돌아온 주소(?code=...&state=...)를 처리한다. 처리했으면 true.
export async function handleCallback(config) {
  const query = new URLSearchParams(location.search);
  const code = query.get("code");
  if (!code) return false;
  const pending = JSON.parse(sessionStorage.getItem(PENDING) || "{}");
  sessionStorage.removeItem(PENDING);
  history.replaceState(null, "", location.pathname + location.hash);
  if (!pending.state || pending.state !== query.get("state")) {
    throw new Error("로그인 확인 값(state)이 맞지 않습니다. 다시 로그인하세요.");
  }
  const response = await fetch(`${config.cognitoDomain}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      code,
      redirect_uri: config.redirectUri,
      code_verifier: pending.verifier,
    }),
  });
  if (!response.ok) throw new Error("로그인에 실패했습니다. 다시 시도하세요.");
  const tokens = await response.json();
  sessionStorage.setItem(TOKENS, JSON.stringify({
    accessToken: tokens.access_token,
    idToken: tokens.id_token,
    expiresAt: Date.now() + tokens.expires_in * 1000,
  }));
  return true;
}

export function session() {
  const data = JSON.parse(sessionStorage.getItem(TOKENS) || "null");
  if (!data || Date.now() > data.expiresAt - 30_000) return null;
  return data;
}

// 화면 표시용. 권한 판단에는 쓰지 않는다(서버가 토큰을 검증한다).
export function userEmail() {
  const data = session();
  if (!data || !data.idToken) return "";
  try {
    const payload = data.idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)).email || "";
  } catch {
    return "";
  }
}

export function clear() {
  sessionStorage.removeItem(TOKENS);
}

export function logout(config) {
  clear();
  const params = new URLSearchParams({ client_id: config.clientId, logout_uri: config.redirectUri });
  location.assign(`${config.cognitoDomain}/logout?${params}`);
}
