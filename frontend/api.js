import { clear, session } from "./auth.js";

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function createApi(config, onUnauthorized) {
  const base = config.apiUrl.replace(/\/$/, "");

  async function request(method, path, body) {
    const auth = session();
    if (!auth) {
      onUnauthorized();
      throw new ApiError(401, "로그인이 필요합니다.");
    }
    const headers = { Authorization: `Bearer ${auth.accessToken}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401) {
      clear();
      onUnauthorized();
      throw new ApiError(401, "로그인이 만료되었습니다.");
    }
    if (response.status === 204) return null;
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new ApiError(response.status, data.message || `요청 실패 (${response.status})`);
    return data;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, body = {}) => request("POST", path, body),
    del: (path) => request("DELETE", path),
  };
}
