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
        : [{ protocol: "proof-client/11", args: ["serve"] }],
    );
    if (outcome.startsWith("ready-")) port.onMessage.emit({ event: "ready", address: "localhost" });
    if (outcome.startsWith("disconnect")) {
      if (outcome === "disconnect-error")
        Object.assign(fake.runtime, { lastError: { message: "host crashed" } });
      port.onDisconnect.emit();
    }
    await assert.rejects(promise, { message });
    closed(port);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  }
});

test(
  "malformed native events fail at the boundary and release ownership",
  { timeout: 5000 },
  async () => {
    for (const [value, message] of [
      [null, "Invalid native event"],
      [{ event: "unknown" }, "Unknown native event"],
      [{ event: "completed", result: { stdout_base64: "" } }, "Invalid HTTP result"],
      [{ event: "ready" }, "Invalid ready event"],
      [{ event: "completed", result: null }, "Invalid completion event"],
      [{ event: "failed" }, "Invalid failure event"],
    ]) {
      const fake = browser();
      const signal = new AbortController().signal;
      const promise = invoke([], (state) => assert.notEqual(state.phase, phases.waiting), signal);
      const port = fake.ports[0];
      assert.ok(port);
      port.onMessage.emit(value);
      await assert.rejects(promise, { message });
      closed(port);
      assert.equal(getEventListeners(signal, "abort").length, 0);
    }
  },
);

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
        const event = new window.Event("submit", { cancelable: true });
        form.dispatchEvent(event);
        assert.equal(event.defaultPrevented, true);
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
          result: {
            stdout_base64: Buffer.from("<script>private</script>🔒").toString("base64"),
            metadata_output: "/fixture/metadata.json",
          },
        }),
      "<script>private</script>🔒\nMetadata: /fixture/metadata.json",
    ],
    [(port) => port.onMessage.emit({ event: "failed", message: "rejected" }), "Failed: rejected"],
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
        protocol: "proof-client/11",
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
  for (const input of ["{", "[1]", '["--url", 1]']) {
    const fake = browser();
    attest.set("request-args", input);
    attest.submit();
    assert.equal(fake.ports.length, 0);
    if (input === "{") assert.ok(attest.output.textContent.startsWith("Failed:"));
    else await attest.settled("Failed: Request arguments must be a JSON array of strings");
  }
  const unavailable = browser();
  unavailable.runtime.connectNative = () => {
    throw Object.freeze({ code: "external failure" });
  };
  attest.set("request-args", "[]");
  attest.submit();
  await attest.settled("Failed: Unknown native failure");
  assert.equal(unavailable.ports.length, 0);

  for (const command of ["serve", "verify"]) {
    const form = operation(command);
    const fake = browser();
    if (command === "verify") {
      for (const name of ["circuit", "proof", "public"]) form.set(name, `/trusted/${name}.json`);
    } else form.set("max-commitment-permutations", "12");
    form.submit();
    form.running();
    const port = fake.ports[0];
    assert.ok(port);
    if (command === "serve") {
      port.onMessage.emit({ event: "ready", address: "localhost" });
      assert.equal(form.output.textContent, "Ready: localhost. Waiting for one attestation.");
    } else
      assert.deepEqual(port.sent, [
        {
          protocol: "proof-client/11",
          args: [
            "verify",
            "--circuit",
            "/trusted/circuit.json",
            "--proof",
            "/trusted/proof.json",
            "--public",
            "/trusted/public.json",
          ],
        },
      ]);
    port.onMessage.emit({ event: "completed", result: { verified: true } });
    await form.settled('Completed\n{\n  "verified": true\n}');
    closed(port);
  }
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
            port.onMessage.emit({ event, address: "localhost", result: {}, message: "rejected" });
        }
        if (command === "serve" && events.join() === "ready,completed,ready") {
          assert.deepEqual(await promise, {});
          assert.deepEqual(observed, ["running", "waiting", "succeeded"]);
        } else if (command === "attest" && events.join() === "completed") {
          assert.deepEqual(await promise, {});
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
