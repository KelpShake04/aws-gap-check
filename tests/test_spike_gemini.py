import unittest

import spike_gemini


def model(name, methods=("generateContent",)):
    return {"name": f"models/{name}", "supportedGenerationMethods": list(methods)}


class FlashCandidatesTest(unittest.TestCase):
    def test_keeps_only_text_flash_models_that_generate(self):
        models = [
            model("gemini-2.5-flash"),
            model("gemini-2.5-pro"),
            model("gemini-2.5-flash-image"),
            model("gemini-2.5-flash-preview-tts"),
            model("text-embedding-004", methods=("embedContent",)),
            model("gemini-2.5-flash-live", methods=("bidiGenerateContent",)),
        ]
        self.assertEqual(spike_gemini.flash_candidates(models), ["gemini-2.5-flash"])

    def test_stable_and_newer_first(self):
        models = [
            model("gemini-2.5-flash"),
            model("gemini-3.6-flash-preview"),
            model("gemini-3.6-flash"),
            model("gemini-3.6-flash-lite"),
        ]
        self.assertEqual(
            spike_gemini.flash_candidates(models),
            ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-3.6-flash-lite",
             "gemini-3.6-flash-preview"],
        )


class CheckShapeTest(unittest.TestCase):
    def test_valid(self):
        result = {"summary": "요약", "risk": "위험", "impact": "영향", "steps": ["조치"]}
        self.assertEqual(spike_gemini.check_shape(result), [])

    def test_reports_problems(self):
        result = {"summary": "가" * 81, "risk": "", "steps": []}
        problems = spike_gemini.check_shape(result)
        self.assertEqual(len(problems), 4)


if __name__ == "__main__":
    unittest.main()
