// @ts-check
const host = "io.github.neotheprogramist.proof_client";
const protocol = "proof-client/8";
const tags = Object.freeze({ ready: "ready", completed: "completed", failed: "failed" });
/** @typedef {{event: "ready", address: string}} Ready */
/** @typedef {{event: "completed", result: object}} Completed */
/** @typedef {{event: "failed", message: string}} Failed */
/** @typedef {Ready | Completed | Failed} Event */
export class NativeError extends Error {
  tag = "native";
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "NativeError";
  }
}
/** @param {unknown} value */
function parse(value) {
  if (typeof value !== "object" || value === null || !("event" in value)) {
    throw new NativeError("Invalid native event");
  }
  switch (value.event) {
    case tags.ready:
      if (!("address" in value) || typeof value.address !== "string") {
        throw new NativeError("Invalid ready event");
      }
      return Object.freeze({ event: tags.ready, address: value.address });
    case tags.completed:
      if (!("result" in value) || typeof value.result !== "object" || value.result === null) {
        throw new NativeError("Invalid completion event");
      }
      return Object.freeze({ event: tags.completed, result: value.result });
    case tags.failed:
      if (!("message" in value) || typeof value.message !== "string") {
        throw new NativeError("Invalid failure event");
      }
      return Object.freeze({ event: tags.failed, message: value.message });
    default:
      throw new NativeError("Unknown native event");
  }
}
/** @param {string[]} args @param {(address: string) => void} ready @param {AbortSignal} signal */
export async function invoke(args, ready, signal) {
  const port = chrome.runtime.connectNative(host);
  const { promise, resolve, reject } = Promise.withResolvers();
  /** @param {unknown} value */
  const message = (value) => {
    try {
      const event = parse(value);
      switch (event.event) {
        case tags.ready:
          ready(event.address);
          break;
        case tags.completed:
          resolve(event.result);
          break;
        case tags.failed:
          reject(new NativeError(event.message));
          break;
        default: {
          /** @type {never} */
          const unreachable = event;
          throw new NativeError(`Unhandled event: ${unreachable}`);
        }
      }
    } catch (error) {
      reject(error);
    }
  };
  const disconnected = () =>
    reject(
      new NativeError(
        chrome.runtime.lastError?.message ?? "Native host disconnected before completion",
      ),
    );
  const cancelled = () =>
    reject(new NativeError("Cancelled. Check output paths before starting a new operation."));
  port.onMessage.addListener(message);
  port.onDisconnect.addListener(disconnected);
  signal.addEventListener("abort", cancelled, { once: true });
  try {
    if (signal.aborted) cancelled();
    else port.postMessage({ protocol, args });
    return await promise;
  } finally {
    port.onMessage.removeListener(message);
    port.onDisconnect.removeListener(disconnected);
    signal.removeEventListener("abort", cancelled);
    port.disconnect();
  }
}
