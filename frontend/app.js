// 화면. 서버와 스캔 결과에서 온 값(리소스 이름 등 공격자가 정할 수 있는 문자열 포함)은
// 모두 textContent로만 넣는다. HTML 문자열을 해석하는 API는 쓰지 않는다(tests/test_frontend.py가 검사).
import * as auth from "./auth.js";
import { createApi } from "./api.js";

const SEVERITY = { critical: "치명", high: "높음", medium: "중간", low: "낮음", informational: "정보" };
const STATUS = {
  PENDING: "검증 전", ACTIVE: "연결됨", FAILED: "실패",
  QUEUED: "대기 중", RUNNING: "스캔 중", PROCESSING: "결과 처리 중", EXPLAINING: "AI 해설 중", DONE: "완료",
};
const FINAL = ["DONE", "FAILED"];
const main = document.getElementById("main");
let user;
let api;
let pollTimer;

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function render(...nodes) {
  main.replaceChildren(...nodes.flat(Infinity).filter(Boolean));
}

function fmt(iso) {
  return iso ? new Date(iso).toLocaleString("ko-KR") : "-";
}

function badge(value, labels = STATUS) {
  return h("span", { class: `badge b-${String(value).toLowerCase()}` }, labels[value] || value);
}

// 외부 링크는 https만 만든다. 그 밖의 값은 글자로만 보여 준다.
function externalLink(url, text) {
  if (typeof url !== "string" || !url.startsWith("https://")) return h("span", {}, text);
  return h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, text);
}

function copyable(text) {
  const button = h("button", {
    type: "button", class: "link",
    onclick: async () => {
      await navigator.clipboard.writeText(text);
      button.textContent = "복사됨";
    },
  }, "복사");
  return h("span", {}, h("code", {}, text), " ", button);
}

function showError(err) {
  if (err && err.status === 401) return;
  render(h("section", { class: "card error" }, h("p", {}, err.message || "오류가 발생했습니다."),
    h("button", { type: "button", onclick: route }, "다시 시도")));
}

// ---------- 로그인 ----------
function landing() {
  clearTimeout(pollTimer);
  document.getElementById("nav").hidden = true;
  const email = h("input", { type: "email", name: "email", autocomplete: "username", required: true, maxlength: "254" });
  const password = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true, maxlength: "128" });
  const result = h("p", { class: "small error-text" });
  render(h("section", { class: "card hero" },
    h("h1", {}, "AWS 계정 빈틈 점검"),
    h("p", {}, "계정을 읽기 전용으로 연결하면 Prowler로 설정상 빈틈을 점검하고, AI가 무엇이 왜 위험한지와 고치는 순서를 한국어로 설명합니다."),
    h("p", { class: "small muted" }, "액세스 키는 받지 않습니다. 연결은 고객 계정의 읽기 전용 Role과 ExternalId로만 합니다."),
    h("form", {
      class: "stack",
      onsubmit: async (event) => {
        event.preventDefault();
        result.textContent = "";
        try {
          await auth.login(api, email.value, password.value);
          await start();
        } catch (err) {
          result.textContent = err.message;
        }
      },
    }, h("label", {}, "이메일 ", email), h("label", {}, "비밀번호 ", password),
    h("button", { type: "submit" }, "로그인"), result),
    h("p", { class: "small muted" }, "계정은 관리자가 만들어 드립니다(셀프 가입 없음).")));
}

function passwordView() {
  clearTimeout(pollTimer);
  const current = h("input", { type: "password", autocomplete: "current-password", required: true, maxlength: "128" });
  const next = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: "10", maxlength: "128" });
  const again = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: "10", maxlength: "128" });
  const result = h("p", { class: "small error-text" });
  render(h("section", { class: "card" },
    h("h1", {}, "비밀번호 바꾸기"),
    user.mustChangePassword ? h("p", {}, "처음 로그인했습니다. 임시 비밀번호를 새 비밀번호(10자 이상)로 바꿔야 쓸 수 있습니다.") : null,
    h("form", {
      class: "stack",
      onsubmit: async (event) => {
        event.preventDefault();
        if (next.value !== again.value) {
          result.textContent = "새 비밀번호 두 칸이 서로 다릅니다.";
          return;
        }
        try {
          await auth.changePassword(api, current.value, next.value);
          history.replaceState(null, "", "#/scans");
          await start();
        } catch (err) {
          result.textContent = err.message;
        }
      },
    }, h("label", {}, "현재(임시) 비밀번호 ", current), h("label", {}, "새 비밀번호 ", next),
    h("label", {}, "새 비밀번호 확인 ", again), h("button", { type: "submit" }, "바꾸기"), result)));
}

// ---------- 계정 연결 ----------
async function connectionsView() {
  const { connections, setup } = await api.get("/connections");
  const rows = connections.map((conn) => h("tr", {},
    h("td", {}, conn.accountId || "-"),
    h("td", {}, badge(conn.status), conn.message ? h("div", { class: "small error-text" }, conn.message) : null),
    h("td", {}, fmt(conn.createdAt)),
    h("td", { class: "actions" },
      conn.status !== "ACTIVE" ? h("button", { type: "button", onclick: () => showSetup(conn, setup) }, "설정·검증") : null,
      h("button", { type: "button", class: "danger", onclick: () => deleteConnection(conn) }, "삭제"))));
  render(
    h("h1", {}, "계정 연결"),
    h("p", {}, "점검할 AWS 계정에 읽기 전용 Role을 만들고 연결합니다."),
    h("button", { type: "button", onclick: createConnection }, "새 연결 만들기"),
    h("div", { id: "setup" }),
    connections.length
      ? h("table", { class: "list" },
        h("thead", {}, h("tr", {}, ["계정", "상태", "만든 시각", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows))
      : h("p", { class: "muted" }, "아직 연결한 계정이 없습니다."));
}

async function createConnection() {
  const { connection, setup } = await api.post("/connections");
  await connectionsView();
  showSetup(connection, setup);
}

function showSetup(conn, setup) {
  const consoleUrl = `https://console.aws.amazon.com/cloudformation/home?region=${user.region}#/stacks/create`;
  const input = h("input", {
    name: "accountId", inputmode: "numeric", pattern: "[0-9]{12}", maxlength: "12",
    required: true, placeholder: "12자리 계정 ID", value: conn.accountId || "",
  });
  const result = h("p", { class: "small" });
  const form = h("form", {
    class: "inline",
    onsubmit: async (event) => {
      event.preventDefault();
      result.textContent = "검증 중…";
      try {
        const { connection } = await api.post(`/connections/${encodeURIComponent(conn.id)}/verify`,
          { accountId: input.value.trim() });
        if (connection.status === "ACTIVE") {
          location.hash = "#/scans";
        } else {
          result.textContent = connection.message || "검증에 실패했습니다.";
          result.className = "small error-text";
        }
      } catch (err) {
        result.textContent = err.message;
        result.className = "small error-text";
      }
    },
  }, input, h("button", { type: "submit" }, "검증"));
  document.getElementById("setup").replaceChildren(h("section", { class: "card" },
    h("h2", {}, "연결 설정"),
    h("ol", { class: "steps" },
      h("li", {}, h("a", { href: setup.templatePath, download: "aws-gap-check-role.yaml" }, "템플릿 다운로드")),
      h("li", {}, "연결할 계정에 로그인해 ", externalLink(consoleUrl, "CloudFormation 콘솔"),
        "에서 템플릿을 업로드하고 스택을 만듭니다. 스택 이름은 ", h("code", {}, setup.stackName),
        ", 마지막 화면에서 IAM 리소스 생성 확인란을 체크합니다."),
      h("li", {}, "파라미터:",
        h("dl", {},
          h("dt", {}, "ServiceAccountId"), h("dd", {}, copyable(setup.serviceAccountId)),
          h("dt", {}, "ExternalId"), h("dd", {}, copyable(conn.externalId)))),
      h("li", {}, "스택이 완료되면 계정 ID를 입력하고 검증합니다.", form, result)),
    h("p", { class: "small muted" },
      `만들어지는 Role(${setup.roleName})은 읽기 전용(SecurityAudit, ViewOnlyAccess)이며, 이 연결의 ExternalId를 아는 이 서비스만 맡을 수 있습니다. 연결을 끊으려면 그 계정에서 스택을 삭제하세요.`)));
}

async function deleteConnection(conn) {
  if (!confirm("이 연결 기록을 삭제할까요? (고객 계정의 Role은 그 계정에서 스택을 지워야 사라집니다)")) return;
  await api.del(`/connections/${encodeURIComponent(conn.id)}`);
  await connectionsView();
}

// ---------- 스캔 목록 ----------
async function scansView() {
  const [{ scans }, { connections }] = await Promise.all([api.get("/scans"), api.get("/connections")]);
  const active = connections.filter((c) => c.status === "ACTIVE");
  const select = h("select", { name: "connectionId" }, active.map((c) => h("option", { value: c.id }, c.accountId)));
  const button = h("button", { type: "submit" }, "스캔 시작");
  const startForm = active.length
    ? h("form", {
      class: "inline",
      onsubmit: async (event) => {
        event.preventDefault();
        button.disabled = true;
        try {
          const { scan } = await api.post("/scans", { connectionId: select.value });
          location.hash = `#/scans/${scan.id}`;
        } catch (err) {
          button.disabled = false;
          alert(err.message);
        }
      },
    }, h("label", {}, "계정 ", select), button)
    : h("p", {}, "먼저 ", h("a", { href: "#/connections" }, "계정을 연결"), "하세요.");
  const rows = scans.map((scan) => h("tr", {},
    h("td", {}, h("a", { href: `#/scans/${scan.id}` }, fmt(scan.createdAt))),
    h("td", {}, scan.accountId || "-"),
    h("td", {}, badge(scan.status)),
    h("td", {}, scan.counts && scan.counts.failedChecks !== undefined
      ? `치명 ${scan.counts.critical} · 높음 ${scan.counts.high} · 실패 항목 ${scan.counts.failedChecks}` : "-")));
  render(
    h("h1", {}, "스캔"),
    h("section", { class: "card" }, startForm,
      h("p", { class: "small muted" }, "핵심 점검 항목(S3 공개, Security Group, IAM, 암호화)을 읽기 전용으로 확인합니다. 보통 몇 분 걸립니다.")),
    scans.length
      ? h("table", { class: "list" },
        h("thead", {}, h("tr", {}, ["시작 시각", "계정", "상태", "결과"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows))
      : h("p", { class: "muted" }, "아직 스캔이 없습니다."));
  if (scans.some((s) => !FINAL.includes(s.status))) pollTimer = setTimeout(route, 10000);
}

// ---------- 리포트 ----------
async function reportView(id) {
  const { scan, findings } = await api.get(`/scans/${encodeURIComponent(id)}`);
  const running = !FINAL.includes(scan.status);
  render(
    h("p", {}, h("a", { href: "#/scans" }, "← 스캔 목록")),
    h("h1", {}, "스캔 결과 ", h("span", { class: "muted" }, scan.accountId || "")),
    h("p", {}, badge(scan.status), " ", fmt(scan.createdAt),
      scan.error ? h("span", { class: "error-text" }, " ", scan.error) : null),
    running ? h("p", { class: "muted" }, "진행 중입니다. 화면이 자동으로 새로 고쳐집니다.") : null,
    countsView(scan.counts),
    findings.length ? priorityView(scan.summary, findings) : null,
    findings.length ? h("h2", {}, `실패한 점검 항목 ${findings.length}개`) : null,
    findings.map(findingCard),
    scan.status === "DONE" && !findings.length ? h("p", {}, "실패한 점검 항목이 없습니다.") : null,
    FINAL.includes(scan.status)
      ? h("button", { type: "button", class: "danger", onclick: () => deleteScan(scan) }, "결과 삭제")
      : null);
  if (running || findings.some((f) => f.explainSource === "pending")) pollTimer = setTimeout(route, 5000);
}

function countsView(counts) {
  if (!counts || counts.failedChecks === undefined) return null;
  return h("div", { class: "counts" },
    Object.keys(SEVERITY).map((sev) => h("div", { class: `count sev-${sev}` },
      h("strong", {}, counts[sev] || 0), h("span", {}, SEVERITY[sev]))),
    h("div", { class: "count" }, h("strong", {}, counts.passed || 0), h("span", {}, "통과")));
}

function priorityView(summary, findings) {
  const titles = Object.fromEntries(findings.map((f) => [f.checkId, f.title || f.checkId]));
  if (summary && summary.top && summary.top.length) {
    return h("section", { class: "card priority" },
      h("h2", {}, "먼저 고칠 것 (AI 우선순위)"),
      h("p", {}, summary.overall),
      h("ol", {}, summary.top.map((item) => h("li", {}, h("strong", {}, titles[item.check_id]), " — ", item.reason))));
  }
  return h("section", { class: "card priority" },
    h("h2", {}, "먼저 고칠 것 (심각도순)"),
    h("ol", {}, findings.slice(0, 3).map((f) => h("li", {}, badge(f.severity, SEVERITY), " ", titles[f.checkId]))));
}

function findingCard(f) {
  const shown = f.resources.length;
  return h("article", { class: `card finding sev-${f.severity}` },
    h("header", {},
      badge(f.severity, SEVERITY), " ",
      h("h3", {}, f.title || f.checkId),
      h("div", { class: "small muted" }, `${f.checkId} · ${f.service} · 리소스 ${f.totalCount}개`)),
    explanationView(f),
    h("details", {},
      h("summary", {}, `영향받는 리소스 ${f.totalCount}개${shown < f.totalCount ? ` (처음 ${shown}개 표시)` : ""}`),
      h("ul", { class: "resources" }, f.resources.map((r) => h("li", {},
        h("code", {}, r.name || r.uid), r.region ? ` ${r.region}` : "",
        r.uid && r.uid !== r.name ? h("div", { class: "small muted" }, r.uid) : null)))),
    f.references && f.references.length
      ? h("p", { class: "small" }, "참고: ", f.references.map((url, i) => [i ? ", " : "", externalLink(url, "Prowler 설명")]))
      : null);
}

function explanationView(f) {
  if (f.explainSource === "pending") return h("p", { class: "muted" }, "AI 해설을 만드는 중…");
  const e = f.explanation || {};
  if (f.explainSource === "prowler") {
    return h("div", { class: "explain fallback" },
      h("p", { class: "small muted" }, "AI 해설을 만들지 못해 Prowler 원문(영어)을 보여 줍니다."),
      e.risk ? h("p", {}, h("strong", {}, "위험 "), e.risk) : null,
      e.steps && e.steps.length ? h("p", {}, h("strong", {}, "권장 조치 "), e.steps[0]) : null);
  }
  return h("div", { class: "explain" },
    h("p", { class: "small muted" }, "AI 해설 (Gemini)"),
    h("p", { class: "lead" }, e.summary),
    h("p", {}, h("strong", {}, "왜 위험한가 "), e.risk),
    h("p", {}, h("strong", {}, "악용되면 "), e.impact),
    h("p", {}, h("strong", {}, "조치 순서")),
    h("ol", {}, (e.steps || []).map((step) => h("li", {}, step))));
}

async function deleteScan(scan) {
  if (!confirm("이 스캔 결과를 지금 삭제할까요? 원본 리포트도 함께 지워집니다.")) return;
  await api.del(`/scans/${encodeURIComponent(scan.id)}`);
  location.hash = "#/scans";
}

// ---------- 시작 ----------
async function route() {
  clearTimeout(pollTimer);
  const hash = location.hash || "#/scans";
  try {
    if (hash.startsWith("#/scans/")) await reportView(decodeURIComponent(hash.slice("#/scans/".length)));
    else if (hash === "#/connections") await connectionsView();
    else if (hash === "#/password") passwordView();
    else await scansView();
  } catch (err) {
    showError(err);
  }
}

async function start() {
  try {
    user = await auth.me(api);
  } catch (err) {
    if (err.status !== 401) showError(err);
    return;
  }
  document.getElementById("nav").hidden = false;
  document.getElementById("user").textContent = user.demo ? `${user.email} (데모 모드)` : user.email;
  if (user.mustChangePassword) {
    passwordView();
    return;
  }
  await route();
}

api = createApi(landing);
window.addEventListener("hashchange", () => user && !user.mustChangePassword && route());
document.getElementById("logout").addEventListener("click", async () => {
  await auth.logout(api).catch(() => {});
  user = undefined;
  landing();
});
start();
