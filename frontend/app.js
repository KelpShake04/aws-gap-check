// 화면. 서버와 스캔 결과에서 온 값(리소스 이름 등 공격자가 정할 수 있는 문자열 포함)은
// 모두 textContent로만 넣는다. HTML 문자열을 해석하는 API는 쓰지 않는다(tests/test_frontend.py가 검사).
import * as auth from "./auth.js";
import { createApi } from "./api.js";

const SEVERITY = { critical: "치명", high: "높음", medium: "중간", low: "낮음", informational: "정보" };
const PARTS = [
  ["ec2_securitygroup_", "sg", "보안 그룹 (네트워크 노출)"],
  ["ec2_ebs_", "ebs", "EBS 스토리지·스냅샷 암호화"],
  ["s3_", "s3", "S3 버킷 공개·암호화"],
  ["iam_", "iam", "IAM 계정·권한·MFA"],
  ["rds_", "rds", "RDS 데이터베이스 보안"],
  ["kms_", "kms", "KMS 키 관리"],
  ["cloudtrail_", "cloudtrail", "CloudTrail 감사 로그"],
];
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

const SVG_NS = "http://www.w3.org/2000/svg";

// 차트용. SVG도 속성과 textContent로만 만든다(인라인 style은 CSP가 막으므로 쓰지 않는다).
function svg(tag, props = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, String(value));
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

function money(amount, currency = "USD") {
  try {
    return amount.toLocaleString("en-US", { style: "currency", currency });
  } catch {
    return `${amount.toFixed(2)} ${currency}`;
  }
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
    h("p", {}, "계정을 읽기 전용으로 연결하면 이번 달 비용을 보여 주고, Prowler로 설정상 빈틈을 점검하며, AI가 무엇이 왜 위험한지와 고치는 순서를 한국어로 설명합니다."),
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
          history.replaceState(null, "", "#/");
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
          location.hash = "#/";
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
      `만들어지는 Role(${setup.roleName})은 읽기 전용(SecurityAudit, ViewOnlyAccess, 비용 조회 ce:GetCostAndUsage·ce:GetCostForecast)이며, 이 연결의 ExternalId를 아는 이 서비스만 맡을 수 있습니다. 연결을 끊으려면 그 계정에서 스택을 삭제하세요.`)));
}

async function deleteConnection(conn) {
  if (!confirm("이 연결 기록을 삭제할까요? (고객 계정의 Role은 그 계정에서 스택을 지워야 사라집니다)")) return;
  await api.del(`/connections/${encodeURIComponent(conn.id)}`);
  await connectionsView();
}

// ---------- 대시보드 ----------
async function dashboardView() {
  const [{ connections }, { scans }] = await Promise.all([api.get("/connections"), api.get("/scans")]);
  const active = connections.filter((c) => c.status === "ACTIVE");
  const waiting = connections.length - active.length;
  const kpis = h("div", { class: "kpis" });
  const costs = new Map();
  const byConn = new Map(active.map((c) => [c.id, scans.filter((s) => s.connectionId === c.id)]));
  const latest = new Map(active.map((c) => [c.id, (byConn.get(c.id) || [])[0]]));
  const refreshKpis = () => kpis.replaceChildren(...kpiTiles(active.length, costs, latest));
  refreshKpis();
  render(
    h("div", { class: "page-head" },
      h("h1", {}, "대시보드"),
      h("span", { class: "muted small" }, `연결된 계정 ${active.length}개`)),
    active.length ? kpis : h("section", { class: "card empty" },
      h("p", {}, "연결된 계정이 없습니다."),
      h("p", { class: "muted" }, "계정을 연결하면 비용과 보안 점검 결과를 여기서 한눈에 볼 수 있습니다."),
      h("a", { class: "button", href: "#/connections" }, "계정 연결하기")),
    waiting ? h("p", { class: "small muted" }, `검증이 끝나지 않은 연결 ${waiting}개 — `,
      h("a", { href: "#/connections" }, "계정 연결에서 마무리"), "하세요.") : null,
    h("div", { class: "accounts" }, active.map((conn) => accountCard(conn, byConn.get(conn.id) || [], (cost) => {
      costs.set(conn.id, cost);
      refreshKpis();
    }))));
  if (scans.some((s) => !FINAL.includes(s.status))) pollTimer = setTimeout(route, 10000);
}

// 전체 계정 요약. 비용은 불러온 계정만 합친다(아직이면 "…", 실패한 계정은 빠진다).
function kpiTiles(accountCount, costs, latest) {
  const loaded = [...costs.values()];
  const ok = loaded.filter((c) => c.status === "OK");
  const pending = costs.size < accountCount;
  const currency = ok.length ? ok[0].currency : "USD";
  const sum = (key) => ok.reduce((total, c) => total + (c[key] || 0), 0);
  const risky = [...latest.values()].reduce((total, s) =>
    total + (s && s.status === "DONE" && s.counts ? (s.counts.critical || 0) + (s.counts.high || 0) : 0), 0);
  const scanned = [...latest.values()].filter((s) => s && s.status === "DONE").length;
  const tile = (label, value, note, tone) => h("div", { class: `kpi ${tone || ""}` },
    h("span", { class: "kpi-label" }, label), h("strong", {}, value), note ? h("span", { class: "kpi-note" }, note) : null);
  return [
    tile("이번 달 사용액", pending ? "…" : money(sum("spent"), currency), "전체 계정 합계"),
    tile("월말 예상", pending ? "…" : money(sum("forecast"), currency), "예측이 있는 계정만"),
    tile("긴급 보안 항목", scanned ? String(risky) : "-", scanned ? "치명 + 높음 (최신 스캔)" : "스캔 결과 없음", risky ? "bad" : ""),
    tile("연결 계정", String(accountCount), `스캔 완료 ${scanned}개`),
  ];
}

function accountCard(conn, accountScans, onCost) {
  const scan = accountScans[0];
  const costBox = h("div", {}, skeleton());
  const refresh = h("button", { type: "button", class: "ghost", disabled: true, onclick: () => loadCost(true) }, "↻ 새로고침");
  async function loadCost(force) {
    refresh.disabled = true;
    if (force) costBox.replaceChildren(skeleton());
    try {
      const path = `/connections/${encodeURIComponent(conn.id)}/cost`;
      const { cost } = force ? await api.post(`${path}/refresh`) : await api.get(path);
      costBox.replaceChildren(costView(cost));
      onCost(cost);
    } catch (err) {
      costBox.replaceChildren(h("p", { class: "error-text" }, err.message));
    }
    refresh.disabled = false;
  }
  loadCost(false);
  const schedulePill = h("span", { class: "pill" });
  const showSchedule = (value) => {
    const label = Object.fromEntries(SCHEDULE)[value];
    schedulePill.className = value === "off" ? "pill" : "pill on";
    schedulePill.textContent = value === "off" ? "자동 점검 꺼짐" : `${label} 자동 점검`;
  };
  showSchedule(conn.schedule);
  return h("section", { class: "card account" },
    h("header", { class: "account-head" },
      h("div", {}, h("span", { class: "eyebrow" }, "AWS 계정"), h("h2", {}, conn.accountId),
        h("div", { class: "pills" }, h("span", { class: "pill ok" }, "연결됨"), schedulePill,
          h("span", { class: "pill" }, scan ? `마지막 점검 ${ago(scan.createdAt)}` : "점검 기록 없음"))),
      refresh),
    h("h3", { class: "block" }, "비용"),
    costBox,
    h("h3", { class: "block" }, "보안 점검"),
    securityView(conn, accountScans),
    h("h3", { class: "block" }, "자동 점검·알림"),
    scheduleView(conn, showSchedule));
}

const SCHEDULE = [["off", "끔"], ["daily", "매일"], ["weekly", "매주"]];

function scheduleView(conn, onChange) {
  const note = h("p", { class: "small muted" });
  const result = h("span", { class: "small" });
  const describe = (value) => {
    const label = Object.fromEntries(SCHEDULE)[value];
    const base = value === "off"
      ? `꺼져 있습니다. 켜면 정해진 주기로 점검하고, 지난번에 없던 치명·높음 항목이 생기면 ${user.email}로 메일을 보냅니다.`
      : `${label} 자동 점검합니다. 지난번에 없던 치명·높음 항목이 생기면 ${user.email}로 메일을 보냅니다.`;
    note.textContent = user.mail || value === "off" ? base : `${base} (이 서버는 메일 발송이 설정되지 않아 메일은 가지 않습니다.)`;
  };
  const select = h("select", {
    "aria-label": "자동 점검 주기",
    onchange: async () => {
      select.disabled = true;
      result.textContent = "";
      try {
        const { connection } = await api.post(`/connections/${encodeURIComponent(conn.id)}/schedule`, { schedule: select.value });
        conn.schedule = connection.schedule;
        describe(connection.schedule);
        onChange(connection.schedule);
      } catch (err) {
        select.value = conn.schedule;
        result.textContent = err.message;
        result.className = "small error-text";
      }
      select.disabled = false;
    },
  }, SCHEDULE.map(([value, label]) => h("option", { value, selected: conn.schedule === value }, label)));
  describe(conn.schedule);
  const test = user.mail ? h("button", {
    type: "button", class: "ghost",
    onclick: async () => {
      test.disabled = true;
      result.className = "small";
      try {
        const { sentTo } = await api.post("/notify/test");
        result.textContent = `${sentTo}로 테스트 메일을 보냈습니다.`;
      } catch (err) {
        result.textContent = err.message;
        result.className = "small error-text";
      }
      test.disabled = false;
    },
  }, "테스트 메일 보내기") : null;
  return h("div", {}, h("div", { class: "schedule-row" }, select, test, result), note);
}

function skeleton() {
  return h("div", { class: "skeleton", "aria-label": "불러오는 중" },
    h("div", { class: "sk-row" }), h("div", { class: "sk-chart" }), h("div", { class: "sk-row short" }));
}

// 지난달 합계와 월말 예상을 비교한 증감. 지난달이 0이면 비교하지 않는다.
function deltaChip(forecast, previous) {
  if (forecast === null || !previous) return null;
  const pct = Math.round(((forecast - previous) / previous) * 100);
  const tone = pct > 0 ? "up" : pct < 0 ? "down" : "flat";
  return h("span", { class: `delta ${tone}` }, `${pct > 0 ? "▲" : pct < 0 ? "▼" : "–"} 지난달 대비 ${Math.abs(pct)}%`);
}

function costView(cost) {
  if (cost.status !== "OK") return h("p", { class: "error-text" }, cost.message);
  const fmtMoney = (amount) => money(amount, cost.currency);
  const peak = Math.max(...cost.daily.map((d) => d.amount), 0.01);
  const total = cost.services.reduce((sum, item) => sum + item.amount, 0) || 1;
  const first = cost.daily[0].date.slice(5);
  const last = cost.daily[cost.daily.length - 1].date.slice(5);
  return h("div", {},
    h("div", { class: "counts three" },
      h("div", { class: "count" }, h("strong", {}, fmtMoney(cost.spent)), h("span", {}, `${cost.month} 사용액`)),
      h("div", { class: "count" }, h("strong", {}, cost.forecast === null ? "-" : fmtMoney(cost.forecast)),
        h("span", {}, "월말 예상"), deltaChip(cost.forecast, cost.previous)),
      h("div", { class: "count" }, h("strong", {}, fmtMoney(cost.previous)), h("span", {}, "지난달"))),
    h("p", { class: "small muted chart-title" }, "최근 30일 일별 비용"),
    svg("svg", { class: "daily", viewBox: "0 0 600 104", role: "img", "aria-label": "최근 30일 일별 비용" },
      svg("text", { x: 0, y: 10, class: "tick" }, fmtMoney(peak)),
      svg("line", { x1: 0, x2: 600, y1: 16.5, y2: 16.5, class: "grid" }),
      cost.daily.map((d, i) => {
        const height = Math.max(0, Math.round((d.amount / peak) * 62));
        return svg("rect", { x: i * 20 + 2, y: 80 - height, width: 16, height, rx: 2,
          class: i === cost.daily.length - 1 ? "bar today" : "bar" }, svg("title", {}, `${d.date} ${fmtMoney(d.amount)}`));
      }),
      svg("line", { x1: 0, x2: 600, y1: 80.5, y2: 80.5, class: "axis" }),
      svg("text", { x: 0, y: 96, class: "tick" }, first),
      svg("text", { x: 600, y: 96, class: "tick end" }, `${last} (오늘)`)),
    cost.services.length ? breakdownView(cost.services, total, fmtMoney) : null,
    h("p", { class: "small muted" }, `크레딧 적용 전 사용액 · 조회 ${fmt(cost.fetchedAt)} · 비용 조회는 건당 $0.01이라 6시간마다 갱신합니다.`));
}

// 서비스별 비용 도넛(상위 5개 + 기타)과 범례
function breakdownView(services, total, fmtMoney) {
  let offset = 25; // 12시 방향에서 시작
  const rings = services.map((item, i) => {
    const pct = (item.amount / total) * 100;
    const ring = svg("circle", { cx: 21, cy: 21, r: 15.9155, class: `ring c${item.name === "기타" ? 5 : i}`,
      "stroke-dasharray": `${pct.toFixed(2)} ${(100 - pct).toFixed(2)}`, "stroke-dashoffset": offset.toFixed(2) },
      svg("title", {}, `${item.name} ${fmtMoney(item.amount)}`));
    offset -= pct;
    return ring;
  });
  return h("div", { class: "breakdown" },
    svg("svg", { class: "donut", viewBox: "0 0 42 42", role: "img", "aria-label": "서비스별 비용 비중" },
      svg("circle", { cx: 21, cy: 21, r: 15.9155, class: "ring c-track", fill: "none" }),
      rings,
      svg("text", { x: 21, y: 22, class: "total" }, fmtMoney(total)),
      svg("text", { x: 21, y: 26.5, class: "sub" }, "이번 달")),
    h("ul", { class: "legend" }, services.map((item, i) => h("li", {},
      h("span", { class: `dot c${item.name === "기타" ? 5 : i}` }),
      h("span", { class: "svc-name", title: item.name }, item.name),
      h("span", { class: "amount" }, fmtMoney(item.amount), " ",
        h("span", { class: "muted" }, `${Math.round((item.amount / total) * 100)}%`))))));
}

// 심각도 분포를 한 줄 누적 막대와 숫자 범례로 보여 준다
function severityBar(counts, scanId) {
  const keys = Object.keys(SEVERITY);
  const total = keys.reduce((sum, key) => sum + (counts[key] || 0), 0);
  let x = 0;
  const rects = total
    ? keys.filter((key) => counts[key]).map((key) => {
      const width = (counts[key] / total) * 100;
      const rect = svg("rect", { x: x.toFixed(2), y: 0, width: width.toFixed(2), height: 10, class: `sev-${key}` });
      x += width;
      return rect;
    })
    : [svg("rect", { x: 0, y: 0, width: 100, height: 10, class: "none" })];
  return h("div", {},
    svg("svg", { class: "sevbar", viewBox: "0 0 100 10", preserveAspectRatio: "none", role: "img", "aria-label": "심각도 분포" }, rects),
    h("div", { class: "sevlegend" },
      keys.map((key) => scanId
        ? h("a", { href: `#/scans/${encodeURIComponent(scanId)}?severity=${key}` }, `${SEVERITY[key]} `, h("strong", {}, counts[key] || 0))
        : h("span", {}, `${SEVERITY[key]} `, h("strong", {}, counts[key] || 0))),
      h("span", {}, "통과 ", h("strong", {}, counts.passed || 0))));
}

function ago(iso) {
  if (!iso) return "-";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "방금 전";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`;
  return `${Math.floor(seconds / 86400)}일 전`;
}

function scanScore(scan) {
  return scan && scan.score && typeof scan.score.risk === "number" && typeof scan.score.security === "number"
    ? scan.score : null;
}

function partOf(finding) {
  const checkId = String((finding && finding.checkId) || "");
  for (const [prefix, key, label] of PARTS) {
    if (checkId.startsWith(prefix)) return { key, label };
  }
  const svc = String((finding && finding.service) || "other").toLowerCase();
  return { key: svc, label: `${svc.toUpperCase()} 설정` };
}

function shortDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${mm}/${dd} ${hh}:${mi}`;
}

function scoreDeltaChip(latest, prev, kind) {
  if (!prev) return null;
  const diff = latest[kind] - prev[kind];
  if (diff === 0) return h("span", { class: "delta flat" }, "– 직전 대비 변동 없음");
  // 문제점 점수(risk)는 낮아질수록 개선(down=초록), 보안 점수(security)는 높아질수록 개선(down=초록)
  const improved = kind === "risk" ? diff < 0 : diff > 0;
  const arrow = diff > 0 ? "▲" : "▼";
  const word = kind === "risk" ? (diff < 0 ? "감소" : "증가") : (diff > 0 ? "상승" : "하락");
  return h("span", { class: `delta ${improved ? "down" : "up"}` }, `${arrow} 직전 대비 ${Math.abs(diff)}점 ${word}`);
}

// 완료된 스캔 이력을 오래된 순으로 정렬해 문제점 점수(가중합) / 보안 점수(100점) 시계열 꺾은선 그래프를 그린다
function scoreTrendView(accountScans, initialKind = "risk") {
  const points = [...accountScans]
    .filter((s) => s.status === "DONE" && scanScore(s))
    .reverse()
    .slice(-12)
    .map((scan) => ({ scan, score: scanScore(scan) }));
  if (!points.length) return null;

  const box = h("div", { class: "trend-box" });
  const draw = (kind) => {
    const latest = points[points.length - 1].score;
    const prev = points.length >= 2 ? points[points.length - 2].score : null;
    const values = points.map((p) => p.score[kind]);
    const maxVal = kind === "security" ? 100 : Math.max(...values, 10);
    const X0 = 36, X1 = 584, W = X1 - X0, Y0 = 18, Y1 = 86, H = Y1 - Y0;
    const n = points.length;
    const coords = points.map((p, i) => {
      const x = n === 1 ? Math.round((X0 + X1) / 2) : Math.round(X0 + (i / (n - 1)) * W);
      const y = Math.round(Y1 - (Math.max(0, Math.min(maxVal, p.score[kind])) / maxVal) * H);
      return { x, y, ...p };
    });
    const polyPoints = coords.map((c) => `${c.x},${c.y}`).join(" ");
    const areaPoints = `${coords[0].x},${Y1} ${polyPoints} ${coords[coords.length - 1].x},${Y1}`;
    const isRisk = kind === "risk";
    const label = isRisk ? "문제점 점수 시계열 추이" : "보안 점수 시계열 추이";

    box.replaceChildren(
      h("div", { class: "trend-head" },
        h("div", { class: "trend-summary" },
          h("span", { class: "small muted" }, isRisk ? "문제점 점수 추이 (낮을수록 안전)" : "보안 점수 추이 (100점 만점)"),
          h("div", { class: "trend-now" },
            h("strong", {}, isRisk ? `${latest.risk}점` : `${latest.security}점`),
            h("span", { class: "small muted" }, isRisk ? `보안 ${latest.security}/100` : `문제점 ${latest.risk}점`),
            scoreDeltaChip(latest, prev, kind))),
        h("div", { class: "trend-toggle", role: "group", "aria-label": "점수 기준 선택" },
          h("button", { type: "button", class: isRisk ? "ghost active" : "ghost", onclick: () => draw("risk") }, "문제점 점수"),
          h("button", { type: "button", class: !isRisk ? "ghost active" : "ghost", onclick: () => draw("security") }, "보안 점수"))),
      svg("svg", { class: `trend ${kind}`, viewBox: "0 0 600 116", role: "img", "aria-label": label },
        svg("text", { x: 0, y: Y0 + 4, class: "tick" }, String(maxVal)),
        svg("line", { x1: X0, x2: X1, y1: Y0 + 0.5, y2: Y0 + 0.5, class: "grid" }),
        svg("text", { x: 0, y: Math.round((Y0 + Y1) / 2) + 4, class: "tick" }, String(Math.round(maxVal / 2))),
        svg("line", { x1: X0, x2: X1, y1: Math.round((Y0 + Y1) / 2) + 0.5, y2: Math.round((Y0 + Y1) / 2) + 0.5, class: "grid" }),
        svg("text", { x: 0, y: Y1 + 4, class: "tick" }, "0"),
        svg("line", { x1: X0, x2: X1, y1: Y1 + 0.5, y2: Y1 + 0.5, class: "axis" }),
        n >= 2 ? svg("polygon", { points: areaPoints, class: "trend-area" }) : null,
        n >= 2 ? svg("polyline", { points: polyPoints, class: "trend-line" }) : null,
        coords.map((c, i) => [
          svg("text", { x: c.x, y: Math.max(12, c.y - 8), class: "trend-val" }, String(c.score[kind])),
          svg("circle", {
            cx: c.x, cy: c.y, r: i === n - 1 ? 5 : 4,
            class: i === n - 1 ? "dot latest" : "dot",
            onclick: () => { location.hash = `#/scans/${c.scan.id}`; },
          }, svg("title", {}, `${fmt(c.scan.createdAt)} · 문제점 ${c.score.risk}점 · 보안 ${c.score.security}점 (치명 ${c.scan.counts.critical || 0}, 높음 ${c.scan.counts.high || 0})`)),
        ]),
        n === 1
          ? svg("text", { x: coords[0].x, y: 106, class: "tick mid" }, shortDate(coords[0].scan.createdAt))
          : [
            svg("text", { x: X0, y: 106, class: "tick" }, shortDate(coords[0].scan.createdAt)),
            n >= 3 ? svg("text", { x: coords[Math.floor(n / 2)].x, y: 106, class: "tick mid" }, shortDate(coords[Math.floor(n / 2)].scan.createdAt)) : null,
            svg("text", { x: X1, y: 106, class: "tick end" }, `${shortDate(coords[n - 1].scan.createdAt)} (최신)`),
          ]),
      h("p", { class: "small muted trend-note" },
        n === 1
          ? "스캔이 2회 이상 쌓이면 시계열 변화 추이 선이 표시됩니다. (가중치: 치명×10, 높음×5, 중간×2, 낮음×1)"
          : "점을 클릭하면 해당 스캔 리포트로 이동합니다. (가중치: 치명×10, 높음×5, 중간×2, 낮음×1)"));
  };
  draw(initialKind);
  return box;
}

function securityView(conn, accountScans) {
  const scan = accountScans[0];
  const startButton = h("button", {
    type: "button",
    onclick: async () => {
      startButton.disabled = true;
      try {
        const { scan: started } = await api.post("/scans", { connectionId: conn.id });
        location.hash = `#/scans/${started.id}`;
      } catch (err) {
        startButton.disabled = false;
        alert(err.message);
      }
    },
  }, "스캔 시작");
  if (!scan) return h("div", { class: "scan-row" }, h("span", { class: "muted" }, "아직 스캔이 없습니다."), startButton);
  if (!FINAL.includes(scan.status)) {
    startButton.disabled = true;
    startButton.textContent = "스캔 중…";
  }
  return h("div", {},
    h("div", { class: "scan-row" },
      h("span", {}, badge(scan.status), " ", h("span", { class: "muted small" }, fmt(scan.createdAt))),
      h("span", { class: "scan-actions" }, h("a", { href: `#/scans/${scan.id}` }, "결과 보기"), startButton)),
    scan.status === "DONE" ? severityBar(scan.counts, scan.id) : null,
    scoreTrendView(accountScans));
}

function scansTrendSection(scans, connections) {
  const done = scans.filter((s) => s.status === "DONE" && scanScore(s));
  if (!done.length) return null;
  const accountLabels = new Map();
  for (const conn of connections) {
    if (conn.accountId) accountLabels.set(conn.id, conn.accountId);
  }
  for (const scan of done) {
    if (!accountLabels.has(scan.connectionId)) accountLabels.set(scan.connectionId, scan.accountId || scan.connectionId);
  }
  const connIds = [...new Set(done.map((s) => s.connectionId))];
  const chartHolder = h("div", {}, scoreTrendView(done.filter((s) => s.connectionId === connIds[0])));
  const acctSelect = connIds.length > 1
    ? h("select", {
      "aria-label": "추이 그래프 계정 선택",
      onchange: () => {
        chartHolder.replaceChildren(scoreTrendView(done.filter((s) => s.connectionId === acctSelect.value)));
      },
    }, connIds.map((id) => h("option", { value: id }, accountLabels.get(id) || id)))
    : h("span", { class: "muted small" }, `계정 ${accountLabels.get(connIds[0]) || "-"}`);
  return h("section", { class: "card" },
    h("div", { class: "page-head" },
      h("h2", { class: "section-title" }, "계정 점수 변화 추이"),
      acctSelect),
    chartHolder);
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
  const rows = scans.map((scan) => {
    const sc = scanScore(scan);
    const sid = encodeURIComponent(scan.id);
    return h("tr", {},
      h("td", {}, h("a", { href: `#/scans/${sid}` }, fmt(scan.createdAt))),
      h("td", {}, scan.accountId || "-"),
      h("td", {}, badge(scan.status)),
      h("td", { class: "scan-links" }, sc
        ? [
          h("span", {}, `문제점 ${sc.risk}점 (보안 ${sc.security}점)`), " · ",
          h("a", { class: "sev-link critical", href: `#/scans/${sid}?severity=critical` }, `치명 ${scan.counts.critical}`), " · ",
          h("a", { class: "sev-link high", href: `#/scans/${sid}?severity=high` }, `높음 ${scan.counts.high}`), " · ",
          h("a", { class: "sev-link", href: `#/scans/${sid}` }, `실패 항목 ${scan.counts.failedChecks}`),
        ]
        : "-"));
  });
  render(
    h("h1", {}, "스캔"),
    h("section", { class: "card" }, startForm,
      h("p", { class: "small muted" }, "핵심 점검 항목(S3 공개, Security Group, IAM, 암호화)을 읽기 전용으로 확인합니다. 보통 몇 분 걸립니다.")),
    scansTrendSection(scans, connections),
    scans.length
      ? h("table", { class: "list" },
        h("thead", {}, h("tr", {}, ["시작 시각", "계정", "상태", "결과"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows))
      : h("p", { class: "muted" }, "아직 스캔이 없습니다."));
  if (scans.some((s) => !FINAL.includes(s.status))) pollTimer = setTimeout(route, 10000);
}

// ---------- 리포트 ----------
async function reportView(id, filterSeverity = "", filterPart = "", filterIsms = "") {
  const { scan, findings, ismsPCovered } = await api.get(`/scans/${encodeURIComponent(id)}`);
  const running = !FINAL.includes(scan.status);
  // 자동 새로 고침 때 사용자가 펼쳐 둔 리소스 목록을 유지한다(같은 스캔일 때만)
  const opened = main.dataset.report === id
    ? new Set([...main.querySelectorAll("details[open]")].map((d) => d.dataset.check)) : new Set();
  const filtered = findings.filter((f) =>
    (!filterSeverity || f.severity === filterSeverity) &&
    (!filterPart || partOf(f).key === filterPart) &&
    (!filterIsms || (f.ismsP || []).some((item) => item.id === filterIsms)));
  const activePartLabel = filterPart ? (PARTS.find(([, k]) => k === filterPart)?.[2] || filterPart.toUpperCase()) : "";
  const ismsItem = filterIsms ? findings.flatMap((f) => f.ismsP || []).find((item) => item.id === filterIsms) : null;
  const activeIsmsLabel = filterIsms ? `ISMS-P ${filterIsms}${ismsItem ? ` ${ismsItem.name}` : ""}` : "";
  const filterNotice = (filterSeverity || filterPart || filterIsms)
    ? h("div", { class: "filter-bar" },
      h("span", {},
        "필터 적용: ",
        h("strong", {}, [filterSeverity ? SEVERITY[filterSeverity] || filterSeverity : "", activePartLabel, activeIsmsLabel].filter(Boolean).join(" · ")),
        ` (${filtered.length}개 항목)`),
      h("a", { href: `#/scans/${encodeURIComponent(scan.id)}` }, "전체 항목 보기"))
    : null;
  render(
    h("p", {}, h("a", { href: "#/scans" }, "← 스캔 목록")),
    h("h1", {}, "스캔 결과 ", h("span", { class: "muted" }, scan.accountId || "")),
    h("p", {}, badge(scan.status), " ", fmt(scan.createdAt),
      scan.error ? h("span", { class: "error-text" }, " ", scan.error) : null),
    running ? h("p", { class: "muted" }, "진행 중입니다. 화면이 자동으로 새로 고쳐집니다.") : null,
    countsView(scan.id, scan.counts, filterSeverity),
    findings.length ? frequentPartsView(scan.id, findings, filterPart) : null,
    findings.length ? ismsView(scan.id, findings, ismsPCovered, filterIsms) : null,
    findings.length ? priorityView(scan.summary, findings) : null,
    findings.length ? h("h2", {}, filterNotice ? `선택한 점검 항목 ${filtered.length}개 (전체 ${findings.length}개)` : `실패한 점검 항목 ${findings.length}개`) : null,
    filterNotice,
    filtered.map((f) => findingCard(f, opened.has(f.checkId), opened.has(`${f.checkId}#code`))),
    findings.length && !filtered.length ? h("p", { class: "muted" }, "선택한 조건에 해당하는 실패 항목이 없습니다.") : null,
    scan.status === "DONE" && !findings.length ? h("p", {}, "실패한 점검 항목이 없습니다.") : null,
    FINAL.includes(scan.status)
      ? h("button", { type: "button", class: "danger", onclick: () => deleteScan(scan) }, "결과 삭제")
      : null);
  main.dataset.report = id;
  if (running || findings.some((f) => f.explainSource === "pending")) pollTimer = setTimeout(route, 5000);
}

function countsView(scanId, counts, activeSeverity) {
  if (!counts || counts.failedChecks === undefined) return null;
  const sid = encodeURIComponent(scanId);
  return h("div", { class: "counts" },
    Object.keys(SEVERITY).map((sev) => {
      const selected = activeSeverity === sev;
      const href = selected ? `#/scans/${sid}` : `#/scans/${sid}?severity=${sev}`;
      return h("a", { href, class: `count sev-${sev}${selected ? " active" : ""}` },
        h("strong", {}, counts[sev] || 0), h("span", {}, SEVERITY[sev]));
    }),
    h("a", { href: `#/scans/${sid}`, class: `count${!activeSeverity ? " active" : ""}` },
      h("strong", {}, counts.passed || 0), h("span", {}, "통과 (전체 보기)")));
}

// 실패한 점검 항목을 보안 영역(발생 파트)별로 집계해 사용자가 가장 자주 실수하는 파트를 보여 준다
function frequentPartsView(scanId, findings, activePart) {
  const byPart = new Map();
  for (const f of findings) {
    const { key, label } = partOf(f);
    const cur = byPart.get(key) || { key, label, checks: 0, resources: 0, urgent: 0 };
    cur.checks += 1;
    cur.resources += f.totalCount || 0;
    if (f.severity === "critical" || f.severity === "high") cur.urgent += 1;
    byPart.set(key, cur);
  }
  const ranked = [...byPart.values()].sort((a, b) =>
    (b.checks - a.checks) || (b.resources - a.resources) || (b.urgent - a.urgent));
  if (!ranked.length) return null;
  const totalChecks = findings.length || 1;
  const top = ranked[0];
  const topPct = Math.round((top.checks / totalChecks) * 100);
  const sid = encodeURIComponent(scanId);
  return h("section", { class: "card parts-card" },
    h("h2", {}, "자주 실수하는 발생 파트 (취약 영역 분석)"),
    h("p", {},
      "가장 빈번하게 문제가 발생한 파트는 ",
      h("strong", {}, top.label),
      ` (실패 항목 ${top.checks}개 · 영향 리소스 ${top.resources}개, 전체의 ${topPct}%)입니다. 파트를 클릭하면 해당 항목만 모아 볼 수 있습니다.`),
    h("ul", { class: "parts-list" }, ranked.map((item) => {
      const pct = Math.max(4, Math.round((item.checks / totalChecks) * 100));
      const selected = activePart === item.key;
      const href = selected ? `#/scans/${sid}` : `#/scans/${sid}?part=${encodeURIComponent(item.key)}`;
      return h("li", {},
        h("a", { href, class: `part-row${selected ? " active" : ""}` },
          h("div", { class: "part-head" },
            h("span", { class: "part-name" },
              h("strong", {}, item.label),
              item.urgent ? [" ", h("span", { class: "badge b-high" }, `치명·높음 ${item.urgent}`)] : null),
            h("span", { class: "small muted" }, `실패 항목 ${item.checks}개 · 리소스 ${item.resources}개 (${Math.round((item.checks / totalChecks) * 100)}%)`)),
          svg("svg", { class: "part-bar", viewBox: "0 0 100 6", preserveAspectRatio: "none", "aria-hidden": "true" },
            svg("rect", { x: 0, y: 0, width: 100, height: 6, class: "track" }),
            svg("rect", { x: 0, y: 0, width: pct, height: 6, class: item.urgent ? "fill urgent" : "fill" }))));
    })));
}

// 2.10.2(클라우드 보안)는 거의 모든 점검이 대응하는 포괄 항목이라 목록 맨 아래에 둔다
const ISMS_BROAD = "2.10.2";

function ismsCompare(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

// 실패한 점검 항목을 KISA ISMS-P 2023 통제 항목별로 묶는다(매핑은 Prowler에 포함된 파일)
function ismsView(scanId, findings, covered, activeIsms) {
  const byItem = new Map();
  for (const f of findings) {
    for (const item of f.ismsP || []) {
      const cur = byItem.get(item.id) || { id: item.id, name: item.name, checks: 0, urgent: 0 };
      cur.checks += 1;
      if (f.severity === "critical" || f.severity === "high") cur.urgent += 1;
      byItem.set(item.id, cur);
    }
  }
  if (!byItem.size) return null;
  const ranked = [...byItem.values()].sort((a, b) =>
    (Number(a.id === ISMS_BROAD) - Number(b.id === ISMS_BROAD)) || (b.urgent - a.urgent) ||
    (b.checks - a.checks) || ismsCompare(a.id, b.id));
  // 포괄 항목(2.10.2)은 거의 모든 점검이 대응해 막대 기준에서 뺀다(그 막대는 100으로 꽉 찬다)
  const max = Math.max(1, ...ranked.filter((item) => item.id !== ISMS_BROAD).map((item) => item.checks));
  const sid = encodeURIComponent(scanId);
  return h("section", { class: "card parts-card" },
    h("h2", {}, "ISMS-P 통제 항목 관점"),
    h("p", {},
      covered ? `핵심 점검이 대응하는 ISMS-P 2023 통제 항목 ${Math.max(covered, byItem.size)}개 중 ` : "ISMS-P 2023 통제 항목 ",
      h("strong", {}, `${byItem.size}개`),
      "에서 미흡한 점검이 나왔습니다. 항목을 누르면 관련 점검만 모아 볼 수 있습니다."),
    h("ul", { class: "parts-list" }, ranked.map((item) => {
      const selected = activeIsms === item.id;
      const href = selected ? `#/scans/${sid}` : `#/scans/${sid}?isms=${encodeURIComponent(item.id)}`;
      return h("li", {},
        h("a", { href, class: `part-row${selected ? " active" : ""}` },
          h("div", { class: "part-head" },
            h("span", { class: "part-name" },
              h("strong", {}, `${item.id} ${item.name}`),
              item.id === ISMS_BROAD ? h("span", { class: "small muted" }, " (포괄 항목)") : null,
              item.urgent ? [" ", h("span", { class: "badge b-high" }, `치명·높음 ${item.urgent}`)] : null),
            h("span", { class: "small muted" }, `미흡 점검 ${item.checks}개`)),
          svg("svg", { class: "part-bar", viewBox: "0 0 100 6", preserveAspectRatio: "none", "aria-hidden": "true" },
            svg("rect", { x: 0, y: 0, width: 100, height: 6, class: "track" }),
            svg("rect", { x: 0, y: 0, width: Math.min(100, Math.max(4, Math.round((item.checks / max) * 100))), height: 6,
              class: item.urgent ? "fill urgent" : "fill" }))));
    })),
    h("p", { class: "small muted" },
      "매핑 출처: Prowler에 포함된 KISA ISMS-P 2023 매핑. 자동 점검으로 확인할 수 있는 기술 항목만 다루며 인증 심사를 대신하지 않습니다."));
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

// 포괄 항목(2.10.2)은 모든 카드에 붙어 정보가 없으므로 칩에서 뺀다
function ismsChips(items) {
  const shown = (items || []).filter((item) => item.id !== ISMS_BROAD);
  return shown.length
    ? h("div", { class: "isms-chips" }, shown.map((item) => h("span", { class: "chip" }, `ISMS-P ${item.id} ${item.name}`)))
    : null;
}

function findingCard(f, isOpen, codeOpen) {
  const shown = f.resources.length;
  return h("article", { class: `card finding sev-${f.severity}` },
    h("header", {},
      badge(f.severity, SEVERITY), " ",
      h("h3", {}, f.title || f.checkId),
      h("div", { class: "small muted" }, `${f.checkId} · ${f.service} · 리소스 ${f.totalCount}개`),
      ismsChips(f.ismsP)),
    explanationView(f),
    h("details", { "data-check": f.checkId, open: isOpen },
      h("summary", {}, `영향받는 리소스 ${f.totalCount}개${shown < f.totalCount ? ` (처음 ${shown}개 표시)` : ""}`),
      h("ul", { class: "resources" }, f.resources.map((r) => h("li", {},
        h("code", {}, r.name || r.uid), r.region ? ` ${r.region}` : "",
        r.uid && r.uid !== r.name ? h("div", { class: "small muted" }, r.uid) : null)))),
    codeView(f, codeOpen),
    f.references && f.references.length
      ? h("p", { class: "small" }, "참고: ", f.references.map((url, i) => [i ? ", " : "", externalLink(url, "Prowler 설명")]))
      : null);
}

const CODE_LABEL = { Other: "콘솔에서", CLI: "AWS CLI", NativeIaC: "CloudFormation", Terraform: "Terraform" };

// Prowler 메타데이터의 공식 예시. 서비스가 대신 실행하지 않으므로 사용자가 값을 바꿔 직접 실행한다
function codeView(f, isOpen) {
  const code = f.remediationCode || {};
  const kinds = Object.keys(CODE_LABEL).filter((kind) => code[kind]);
  if (!kinds.length) return null;
  return h("details", { class: "remediation", "data-check": `${f.checkId}#code`, open: isOpen },
    h("summary", {}, "공식 수정 예시 (Prowler 원문)"),
    h("p", { class: "small muted" },
      "<...>로 표시된 자리를 내 리소스 값으로 바꾸고, 내용을 확인한 뒤 직접 실행하세요. 이 서비스는 자동으로 고치지 않습니다."),
    kinds.map((kind) => [h("h4", {}, CODE_LABEL[kind]), h("pre", {}, h("code", {}, code[kind]))]));
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
  const hash = location.hash || "#/";
  const section = hash.startsWith("#/scans") ? "#/scans" : hash;
  for (const link of document.querySelectorAll("#nav a")) link.classList.toggle("active", link.getAttribute("href") === section);
  try {
    if (hash.startsWith("#/scans/")) {
      const [rawId, rawQuery = ""] = hash.slice("#/scans/".length).split("?", 2);
      const params = new URLSearchParams(rawQuery);
      await reportView(decodeURIComponent(rawId), params.get("severity") || "", params.get("part") || "",
        params.get("isms") || "");
    } else if (hash === "#/scans") await scansView();
    else if (hash === "#/connections") await connectionsView();
    else if (hash === "#/password") passwordView();
    else await dashboardView();
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
