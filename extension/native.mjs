// @ts-check
const host = "io.github.neotheprogramist.proof_client";
const protocol = "proof-client/11";
const tags = Object.freeze({ ready: "ready", completed: "completed", failed: "failed" });
/** @typedef {{event: "ready", address: string}} Ready */
/** @typedef {{event: "completed", result: object, text: string}} Completed */
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
/** @param {unknown} error */
function nativeError(error) {
  return new NativeError(error instanceof Error ? error.message : "Unknown native failure");
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
      return Object.freeze({
        event: tags.completed,
        result: value.result,
        text: resultText(value.result),
      });
    case tags.failed:
      if (!("message" in value) || typeof value.message !== "string") {
        throw new NativeError("Invalid failure event");
      }
      return Object.freeze({ event: tags.failed, message: value.message });
    default:
      throw new NativeError("Unknown native event");
  }
}
/** @param {object} result */
function resultText(result) {
  if ("stdout_base64" in result) {
    if (
      typeof result.stdout_base64 !== "string" ||
      !("metadata_output" in result) ||
      typeof result.metadata_output !== "string"
    ) {
      throw new NativeError("Invalid HTTP result");
    }
    const bytes = Uint8Array.from(atob(result.stdout_base64), (byte) => byte.charCodeAt(0));
    return `${new TextDecoder().decode(bytes)}\nMetadata: ${result.metadata_output}`;
  }
  return `Completed\n${JSON.stringify(result, null, 2)}`;
}
export const phases = Object.freeze({
  idle: "idle",
  running: "running",
  waiting: "waiting",
  succeeded: "succeeded",
  failed: "failed",
  cancelled: "cancelled",
});
/** @typedef {{phase: "idle"}} Idle */
/** @typedef {{phase: "running", command: string | undefined}} Running */
/** @typedef {{phase: "waiting", address: string}} Waiting */
/** @typedef {{phase: "succeeded", result: object, text: string}} Succeeded */
/** @typedef {{phase: "failed", error: Error}} Failure */
/** @typedef {{phase: "cancelled"}} Cancelled */
/** @typedef {Idle | Running | Waiting | Succeeded | Failure | Cancelled} State */
/** @typedef {{event: "cancel"}} Cancel */
/** @typedef {Event | Cancel} Transition */
/** @param {State} state */
export function active(state) {
  return state.phase === phases.running || state.phase === phases.waiting;
}
/** @param {State} state @param {Transition} event */
export function step(state, event) {
  if (!active(state)) return state;
  switch (event.event) {
    case tags.ready:
      switch (state.phase) {
        case phases.running:
          if (state.command !== "serve") throw new NativeError("Unexpected ready event");
          return Object.freeze({ phase: phases.waiting, address: event.address });
        case phases.waiting:
          throw new NativeError("Unexpected ready event");
      }

    case tags.completed:
      switch (state.phase) {
        case phases.running:
          if (state.command === "serve") throw new NativeError("Serve completed before ready");
          break;
        // Stryker disable next-line ConditionalExpression: deleting this empty final case is equivalent; it records the closed phase union.
        case phases.waiting:
          break;
      }
      return Object.freeze({
        phase: phases.succeeded,
        result: event.result,
        text: event.text,
      });
    case tags.failed:
      return Object.freeze({ phase: phases.failed, error: new NativeError(event.message) });
    case "cancel":
      return Object.freeze({ phase: phases.cancelled });
    // Stryker disable next-line all: the closed event union is checked by TypeScript.
    default: {
      /** @type {never} */
      const unreachable = event;
      // Stryker disable next-line all: unreachable for the closed event union.
      throw new NativeError(`Unhandled event: ${unreachable}`);
    }
  }
}
/** @param {string[]} args @param {(state: State) => void} observe @param {AbortSignal} signal */
export async function invoke(args, observe, signal) {
  /** @type {State} */
  let state = Object.freeze({ phase: phases.running, command: args[0] });
  const port = chrome.runtime.connectNative(host);
  const { promise, resolve, reject } = Promise.withResolvers();
  /** @param {Transition} event */
  const transition = (event) => {
    const next = step(state, event);
    if (next === state) return;
    state = next;
    try {
      observe(state);
    } catch (error) {
      state = Object.freeze({
        phase: phases.failed,
        error: nativeError(error),
      });
    }
    switch (state.phase) {
      case phases.succeeded:
        resolve(state.result);
        break;
      case phases.failed:
        reject(state.error);
        break;
      case phases.cancelled:
        reject(new NativeError("Cancelled. Check output paths before starting a new operation."));
        break;
      case phases.idle:
      case phases.waiting:
        break;
      // Stryker disable next-line all: TypeScript checks the closed state union.
      default: {
        /** @type {never} */
        const unreachable = state;
        // Stryker disable next-line all: unreachable for the closed state union.
        throw new NativeError(`Unhandled state: ${unreachable}`);
      }
    }
  };
  /** @param {unknown} value */
  const message = (value) => {
    try {
      transition(parse(value));
    } catch (error) {
      transition({
        event: "failed",
        message: nativeError(error).message,
      });
    }
  };
  const disconnected = () => {
    transition({
      event: "failed",
      message: chrome.runtime.lastError?.message ?? "Native host disconnected before completion",
    });
  };
  const cancelled = () => {
    transition({ event: "cancel" });
  };
  port.onMessage.addListener(message);
  port.onDisconnect.addListener(disconnected);
  signal.addEventListener("abort", cancelled);
  try {
    observe(state);
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
