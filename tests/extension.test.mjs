// @ts-check
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { readFile } from "node:fs/promises";
import { setImmediate } from "node:timers/promises";
import test from "node:test";
import { JSDOM } from "jsdom";
import { invoke, NativeError, phases } from "../extension/native.mjs";

function events() {
  /** @type {Set<(...args: any[]) => void>} */
  const listeners = new Set();
  return {
    listeners,
    /** @param {(...args: any[]) => void} listener */
    addListener(listener) {
      listeners.add(listener);
    },
    /** @param {(...args: any[]) => void} listener */
    removeListener(listener) {
      listeners.delete(listener);
    },
    /** @param {unknown[]} args */
    emit(...args) {
      for (const listener of listeners) listener(...args);
    },
  };
}
function nativePort() {
  return {
    onMessage: events(),
    onDisconnect: events(),
    sent: /** @type {unknown[]} */ ([]),
    disconnected: 0,
    /** @param {unknown} value */
    postMessage(value) {
      this.sent.push(value);
    },
    disconnect() {
      this.disconnected++;
    },
  };
}
function browser() {
  const ports = /** @type {ReturnType<typeof nativePort>[]} */ ([]);
  const runtime = {
    lastError: undefined,
    /** @param {string} host */
    connectNative(host) {
      assert.equal(host, "io.github.neotheprogramist.proof_client");
      const port = nativePort();
      ports.push(port);
      return port;
    },
  };
  const fake = {
    runtime,
  };
  globalThis.chrome = /** @type {typeof chrome} */ (/** @type {unknown} */ (fake));
  return { ...fake, ports };
}
/** @param {ReturnType<typeof browser>["ports"][number]} port */
function closed(port) {
  assert.equal(port.disconnected, 1);
  assert.equal(port.onMessage.listeners.size, 0);
  assert.equal(port.onDisconnect.listeners.size, 0);
}

test("native setup and observer failures release owned resources", { timeout: 5000 }, async () => {
  for (const [outcome, message] of Object.entries({
    "disconnect-error": "host crashed",
    preabort: "Cancelled. Check output paths before starting a new operation.",
    "send-error": "send failed",
    "ready-error": "ready failed",
  })) {
    const fake = browser();
    const controller = new AbortController();
    if (outcome === "preabort") controller.abort();
    if (outcome === "send-error") {
      const connect = fake.runtime.connectNative.bind(fake.runtime);
      fake.runtime.connectNative = (host) => {
        const port = connect(host);
        port.postMessage = () => {
          throw new Error("send failed");
        };
        return port;
      };
    }
    const promise = invoke(
      ["serve"],
      (state) => {
        if (state.phase === phases.waiting) {
          throw new Error("ready failed");
        }
      },
      controller.signal,
    );
    const port = fake.ports[0];
    assert.ok(port);
    assert.deepEqual(
      port.sent,
      ["preabort", "send-error"].includes(outcome)
        ? []
        : [{ protocol: "proof-client/12", args: ["serve"] }],
    );
    if (outcome === "ready-error") port.onMessage.emit({ event: "ready", address: "localhost" });
    if (outcome === "disconnect-error") {
      Object.assign(fake.runtime, { lastError: { message: "host crashed" } });
      port.onDisconnect.emit();
    }
    await assert.rejects(promise, { message });
    closed(port);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  }
});

/** @param {import("node:test").TestContext} context @param {string} html */
function page(context, html) {
  const dom = new JSDOM(html);
  context.after(() => dom.window.close());
  for (const name of [
    "window",
    "document",
    "HTMLFieldSetElement",
    "HTMLOutputElement",
    "HTMLButtonElement",
    "FormData",
  ]) {
    const previous = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, {
      value: name === "window" ? dom.window : dom.window[name],
      configurable: true,
    });
    context.after(() => {
      if (previous) Object.defineProperty(globalThis, name, previous);
      else Reflect.deleteProperty(globalThis, name);
    });
  }
  return dom.window;
}

test("page preserves arguments, renders safely, and releases each operation", async (context) => {
  const window = page(
    context,
    await readFile(new URL("../extension/index.html", import.meta.url), "utf8"),
  );
  const added = context.mock.method(window.EventTarget.prototype, "addEventListener");
  const removed = context.mock.method(window.EventTarget.prototype, "removeEventListener");
  await import("../extension/page.mjs");
  /** @param {string} id */
  function operation(id) {
    const form = window.document.querySelector(`#${id}`);
    assert.ok(form instanceof window.HTMLFormElement);
    const fields = form.querySelector("fieldset");
    const output = form.querySelector("output");
    const cancel = form.querySelector('button[type="button"]');
    assert.ok(fields && output && cancel instanceof window.HTMLButtonElement);
    assert.equal(output.textContent, "");
    return {
      output,
      cancel,
      /** @param {string} name @param {string} value */
      set(name, value) {
        const input = form.querySelector(`[name="${name}"]`);
        assert.ok(
          input instanceof window.HTMLInputElement || input instanceof window.HTMLTextAreaElement,
        );
        input.value = value;
      },
      submit() {
        assert.equal(form.checkValidity(), true);
        form.requestSubmit();
      },
      running() {
        assert.equal(fields.disabled, true);
        assert.equal(cancel.disabled, false);
        assert.equal(output.textContent, "Running…");
      },
      /** @param {string} text */
      async settled(text) {
        await setImmediate();
        assert.equal(fields.disabled, false);
        assert.equal(cancel.disabled, true);
        assert.equal(output.textContent, text);
        assert.equal(output.querySelector("script"), null);
        for (const call of added.mock.calls.filter((call) =>
          ["click", "pagehide"].includes(call.arguments[0]),
        )) {
          assert.ok(
            removed.mock.calls.some(
              (removal) =>
                removal.this === call.this &&
                removal.arguments[0] === call.arguments[0] &&
                removal.arguments[1] === call.arguments[1],
            ),
            "operation listener was not removed",
          );
        }
      },
    };
  }
  const attest = operation("attest");
  attest.set("verifier", "127.0.0.1:7047");
  attest.set("data-dir", "/fixture");
  attest.set(
    "request-args",
    JSON.stringify(["--url", "https://localhost/balance", "--data-raw", ""]),
  );
  /** @type {Array<[(port: ReturnType<typeof nativePort>) => void, string]>} */
  const outcomes = [
    [
      (port) =>
        port.onMessage.emit({
          event: "completed",
          result: "Local plaintext: <script>private</script>\nRecord: /fixture/metadata.json",
        }),
      "Local plaintext: <script>private</script>\nRecord: /fixture/metadata.json",
    ],
    [() => attest.cancel.click(), "Cancelled. Check output paths before starting a new operation."],
    [
      () => window.dispatchEvent(new window.Event("pagehide")),
      "Cancelled. Check output paths before starting a new operation.",
    ],
  ];
  for (const [finish, text] of outcomes) {
    const fake = browser();
    attest.submit();
    attest.running();
    const port = fake.ports[0];
    assert.ok(port);
    assert.deepEqual(port.sent, [
      {
        protocol: "proof-client/12",
        args: [
          "attest",
          "--verifier",
          "127.0.0.1:7047",
          "--data-dir",
          "/fixture",
          "--url",
          "https://localhost/balance",
          "--data-raw",
          "",
        ],
      },
    ]);
    finish(port);
    await attest.settled(text);
    closed(port);
  }
  const invalid = browser();
  attest.set("request-args", '["--url", 1]');
  attest.submit();
  await attest.settled("Failed: Request arguments must be a JSON array of strings");
  assert.equal(invalid.ports.length, 0);

  const serve = operation("serve");
  const fake = browser();
  serve.set("max-commitment-permutations", "12");
  serve.set("server-name", "localhost");
  serve.set("data-dir", "/fixture");
  serve.submit();
  serve.running();
  const port = fake.ports[0];
  assert.ok(port);
  assert.deepEqual(port.sent, [
    {
      protocol: "proof-client/12",
      args: [
        "serve",
        "--max-commitment-permutations",
        "12",
        "--server-name",
        "localhost",
        "--data-dir",
        "/fixture",
      ],
    },
  ]);
  port.onMessage.emit({ event: "ready", address: "localhost" });
  assert.equal(serve.output.textContent, "Ready: localhost. Waiting for one attestation.");
  port.onMessage.emit({ event: "completed", result: "Verified report" });
  await serve.settled("Verified report");
  closed(port);
});

test(
  "native lifecycle enforces ordering, settles once, and releases ownership",
  { timeout: 5000 },
  async () => {
    for (const command of ["serve", "attest"]) {
      for (const events of [
        ["ready", "ready"],
        ["completed"],
        ["failed", "ready"],
        ["cancel", "ready"],
        ["ready", "completed", "ready"],
      ]) {
        const fake = browser();
        const controller = new AbortController();
        const observed = /** @type {string[]} */ ([]);
        const promise = invoke([command], (state) => observed.push(state.phase), controller.signal);
        const port = fake.ports[0];
        assert.ok(port);
        for (const event of events) {
          if (event === "cancel") controller.abort();
          else
            port.onMessage.emit({
              event,
              address: "localhost",
              result: "Verified report",
              message: "rejected",
            });
        }
        if (command === "serve" && events.join() === "ready,completed,ready") {
          assert.equal(await promise, "Verified report");
          assert.deepEqual(observed, ["running", "waiting", "succeeded"]);
        } else if (command === "attest" && events.join() === "completed") {
          assert.equal(await promise, "Verified report");
          assert.deepEqual(observed, ["running", "succeeded"]);
        } else {
          await assert.rejects(promise, NativeError);
          assert.equal(observed.at(-1), events[0] === "cancel" ? "cancelled" : "failed");
        }
        const settled = [...observed];
        port.onDisconnect.emit();
        controller.abort();
        assert.deepEqual(observed, settled);
        closed(port);
        assert.equal(getEventListeners(controller.signal, "abort").length, 0);
      }
    }
  },
);
