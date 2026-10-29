import io
import json
import unittest
import urllib.error

from gapcheck import llm

KEY = "test-key-must-never-leak-0123456789"
SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
}


def ok_payload(obj, **candidate_extra):
    candidate = {
        "content": {"parts": [{"text": json.dumps(obj, ensure_ascii=False)}]},
        "finishReason": "STOP",
    }
    candidate.update(candidate_extra)
    return {"candidates": [candidate]}


def http_error(code, body):
    raw = json.dumps(body).encode() if isinstance(body, dict) else body
    return urllib.error.HTTPError(
        "https://example.invalid", code, "error", {}, io.BytesIO(raw)
    )


class FakeOpener:
    """urllib.request.urlopen 대신 넣는 가짜. 요청을 기록하고 정해진 응답을 돌려준다."""

    def __init__(self, payload=None, error=None, raw=None):
        self.payload = payload
        self.error = error
        self.raw = raw
        self.requests = []
        self.timeouts = []

    def __call__(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        if self.raw is not None:
            return io.BytesIO(self.raw)
        return io.BytesIO(json.dumps(self.payload).encode())


def call(opener, **kwargs):
    return llm.generate_json(
        "system text", "user text", SCHEMA,
        model="gemini-test-flash", api_key=KEY, opener=opener, **kwargs
    )


class RequestFormatTest(unittest.TestCase):
    def setUp(self):
        self.opener = FakeOpener(ok_payload({"summary": "요약"}))
        call(self.opener, timeout=12)
        self.request = self.opener.requests[0]
        self.body = json.loads(self.request.data)

    def test_key_is_sent_in_header_not_url(self):
        self.assertEqual(self.request.get_header("X-goog-api-key"), KEY)
        self.assertNotIn(KEY, self.request.full_url)

    def test_posts_to_generate_content_of_model(self):
        self.assertEqual(self.request.get_method(), "POST")
        self.assertTrue(
            self.request.full_url.endswith("/models/gemini-test-flash:generateContent")
        )

    def test_models_prefix_is_not_duplicated(self):
        opener = FakeOpener(ok_payload({"summary": "요약"}))
        llm.generate_json("s", "u", SCHEMA, model="models/gemini-test-flash",
                          api_key=KEY, opener=opener)
        self.assertNotIn("models/models/", opener.requests[0].full_url)

    def test_body_requests_json_with_schema(self):
        config = self.body["generationConfig"]
        self.assertEqual(config["responseMimeType"], "application/json")
        self.assertEqual(config[llm.SCHEMA_FIELD], SCHEMA)

    def test_system_and_user_prompts_are_separate(self):
        self.assertEqual(self.body["systemInstruction"]["parts"][0]["text"], "system text")
        self.assertEqual(self.body["contents"][0]["role"], "user")
        self.assertEqual(self.body["contents"][0]["parts"][0]["text"], "user text")

    def test_timeout_is_passed(self):
        self.assertEqual(self.opener.timeouts, [12])


class ResponseTest(unittest.TestCase):
    def test_returns_parsed_object(self):
        result = call(FakeOpener(ok_payload({"summary": "공개 버킷"})))
        self.assertEqual(result, {"summary": "공개 버킷"})

    def test_thought_parts_are_ignored(self):
        payload = {"candidates": [{
            "content": {"parts": [
                {"text": "생각 중...", "thought": True},
                {"text": '{"summary": "결과"}'},
            ]},
            "finishReason": "STOP",
        }]}
        self.assertEqual(call(FakeOpener(payload)), {"summary": "결과"})

    def test_blocked_prompt(self):
        payload = {"promptFeedback": {"blockReason": "SAFETY"}}
        with self.assertRaises(llm.BlockedResponse):
            call(FakeOpener(payload))

    def test_safety_finish_reason_is_blocked(self):
        with self.assertRaises(llm.BlockedResponse):
            call(FakeOpener(ok_payload({"summary": "x"}, finishReason="SAFETY")))

    def test_truncated_output_is_invalid(self):
        with self.assertRaises(llm.InvalidResponse):
            call(FakeOpener(ok_payload({"summary": "x"}, finishReason="MAX_TOKENS")))

    def test_no_candidates_is_invalid(self):
        with self.assertRaises(llm.InvalidResponse):
            call(FakeOpener({"candidates": []}))

    def test_non_json_text_is_invalid(self):
        payload = {"candidates": [{
            "content": {"parts": [{"text": "JSON이 아닌 문장"}]},
            "finishReason": "STOP",
        }]}
        with self.assertRaises(llm.InvalidResponse):
            call(FakeOpener(payload))

    def test_json_array_is_invalid(self):
        with self.assertRaises(llm.InvalidResponse):
            call(FakeOpener(ok_payload(["not", "object"])))

    def test_non_json_api_body_is_invalid(self):
        with self.assertRaises(llm.InvalidResponse):
            call(FakeOpener(raw=b"<html>gateway error</html>"))


class ErrorTest(unittest.TestCase):
    def test_rate_limit_reads_retry_delay(self):
        body = {"error": {"code": 429, "message": "quota", "details": [
            {"@type": "type.googleapis.com/google.rpc.QuotaFailure"},
            {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "17s"},
        ]}}
        with self.assertRaises(llm.RateLimited) as ctx:
            call(FakeOpener(error=http_error(429, body)))
        self.assertEqual(ctx.exception.retry_after, 17.0)

    def test_rate_limit_without_delay(self):
        with self.assertRaises(llm.RateLimited) as ctx:
            call(FakeOpener(error=http_error(429, b"not json")))
        self.assertIsNone(ctx.exception.retry_after)

    def test_http_error_includes_status_and_message(self):
        body = {"error": {"code": 400, "message": "Invalid JSON payload"}}
        with self.assertRaises(llm.LLMError) as ctx:
            call(FakeOpener(error=http_error(400, body)))
        self.assertIn("400", str(ctx.exception))
        self.assertIn("Invalid JSON payload", str(ctx.exception))

    def test_http_error_message_never_contains_key(self):
        body = {"error": {"code": 400, "message": f"API key {KEY} not valid"}}
        with self.assertRaises(llm.LLMError) as ctx:
            call(FakeOpener(error=http_error(400, body)))
        self.assertNotIn(KEY, str(ctx.exception))

    def test_errors_do_not_chain_original_exception(self):
        with self.assertRaises(llm.LLMError) as ctx:
            call(FakeOpener(error=http_error(500, {"error": {"message": "boom"}})))
        self.assertTrue(ctx.exception.__suppress_context__)

    def test_network_error(self):
        error = urllib.error.URLError("connection refused")
        with self.assertRaises(llm.LLMError) as ctx:
            call(FakeOpener(error=error))
        self.assertNotIn(KEY, str(ctx.exception))

    def test_timeout_error(self):
        with self.assertRaises(llm.TransientError):
            call(FakeOpener(error=TimeoutError()))

    def test_server_overload_is_transient_but_client_error_is_not(self):
        with self.assertRaises(llm.TransientError):
            call(FakeOpener(error=http_error(503, {"error": {"message": "high demand"}})))
        with self.assertRaises(llm.LLMError) as ctx:
            call(FakeOpener(error=http_error(400, {"error": {"message": "bad"}})))
        self.assertNotIsInstance(ctx.exception, llm.TransientError)


class ListModelsTest(unittest.TestCase):
    def test_follows_pages(self):
        pages = [
            {"models": [{"name": "models/a"}], "nextPageToken": "p2"},
            {"models": [{"name": "models/b"}]},
        ]
        requests = []

        def opener(request, timeout):
            requests.append(request)
            return io.BytesIO(json.dumps(pages[len(requests) - 1]).encode())

        models = llm.list_models(KEY, opener=opener)
        self.assertEqual([m["name"] for m in models], ["models/a", "models/b"])
        self.assertIn("pageToken=p2", requests[1].full_url)
        for request in requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertNotIn(KEY, request.full_url)


if __name__ == "__main__":
    unittest.main()
