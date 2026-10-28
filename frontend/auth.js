// 앱 자체 로그인. 비밀번호 확인과 세션 관리는 서버가 하고, 화면은 결과만 받는다.
export const me = (api) => api.get("/me");
export const login = (api, email, password) => api.post("/login", { email, password });
export const changePassword = (api, currentPassword, newPassword) =>
  api.post("/password", { currentPassword, newPassword });
export const logout = (api) => api.post("/logout");
