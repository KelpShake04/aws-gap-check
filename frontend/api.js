// 같은 출처의 /api/* 호출. 세션은 HttpOnly 쿠키라 스크립트가 토큰을 다루지 않는다.
// 상태를 바꾸는 요청에 붙는 X-Requested-With 헤더는 서버의 CSRF 확인용이다.
export class ApiError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function createApi(onUnauthorized) {
  async function request(method, path, body) {
    const headers = { "X-Requested-With": "gapcheck" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(`/api${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 204) return null;
    const data = await response.json().catch(() => ({}));
    // 로그인 요청의 401은 "비밀번호가 틀림"이라 화면에 그대로 보여 준다
    if (response.status === 401 && path !== "/login") {
      onUnauthorized();
      throw new ApiError(401, "로그인이 필요합니다.", "unauthorized");
    }
    if (!response.ok) throw new ApiError(response.status, data.message || `요청 실패 (${response.status})`, data.error);
    return data;
  }

  return {
    get: (path) => request("GET", path),
    post: (path, body = {}) => request("POST", path, body),
    del: (path) => request("DELETE", path),
  };
}
