import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "model_bridge", ROOT / "tools" / "model_bridge.py")
MODEL_BRIDGE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODEL_BRIDGE)


class ModelBridgeTests(unittest.TestCase):
    def test_rewrites_model_and_scaled_temperature(self):
        body = json.dumps({
            "model": "fast",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 200,
            "temperature_scale": 1000,
        }).encode()
        value = json.loads(MODEL_BRIDGE.rewrite_request(body, "gpt-test"))
        self.assertEqual(value["model"], "gpt-test")
        self.assertEqual(value["temperature"], 0.2)
        self.assertNotIn("temperature_scale", value)

    def test_rejects_invalid_shape_and_oversize(self):
        with self.assertRaises(ValueError):
            MODEL_BRIDGE.rewrite_request(b"{}", None)
        with self.assertRaises(ValueError):
            MODEL_BRIDGE.rewrite_request(
                b"x" * (MODEL_BRIDGE.MAX_REQUEST_BYTES + 1), None)

    def test_renders_messages_for_toolless_codex_backend(self):
        body = json.dumps({
            "messages": [
                {"role": "system", "content": "Return JSON."},
                {"role": "user", "content": "Write the file."},
            ],
        }).encode()
        prompt = MODEL_BRIDGE.render_codex_prompt(body)
        self.assertIn("[system]\nReturn JSON.", prompt)
        self.assertIn("[user]\nWrite the file.", prompt)
        self.assertIn("Do not use shell", prompt)


if __name__ == "__main__":
    unittest.main()
