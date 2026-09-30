// @ts-check
import { invoke, NativeError, active, phases } from "./native.mjs";
for (const form of document.querySelectorAll("form")) {
  const fields = form.querySelector("fieldset");
  const output = form.querySelector("output");
  const cancel = form.querySelector('button[type="button"]');
  if (
    !(fields instanceof HTMLFieldSetElement) ||
    !(output instanceof HTMLOutputElement) ||
    !(cancel instanceof HTMLButtonElement)
  ) {
    throw new NativeError("Operation form is incomplete");
  }
  if (form.id === "serve") {
    const suite = form.elements.namedItem("commitment-hash");
    const budget = form.elements.namedItem("max-commitment-permutations");
    if (
      !(suite instanceof window.HTMLSelectElement) ||
      !(budget instanceof window.HTMLInputElement)
    )
      throw new NativeError("Commitment controls are incomplete");
    const updateBudget = () => {
      budget.disabled = suite.value === "blake3";
      budget.required = !budget.disabled;
    };
    suite.addEventListener("change", updateBudget);
    updateBudget();
  }
  /** @param {import("./native.mjs").State} state */
  const render = (state) => {
    fields.disabled = active(state);
    cancel.disabled = !active(state);
    switch (state.phase) {
      case phases.idle:
        output.textContent = "";
        break;
      case phases.running:
        output.textContent = "Running…";
        break;
      case phases.waiting:
        output.textContent = `Ready: ${state.address}. Waiting for one attestation.`;
        break;
      case phases.succeeded:
        output.textContent = state.result;
        break;
      case phases.failed:
        output.textContent = `Failed: ${state.error.message}`;
        break;
      case phases.cancelled:
        output.textContent = "Cancelled. Check output paths before starting a new operation.";
        break;
      default: {
        /** @type {never} */
        const unreachable = state;
        throw new NativeError(`Unhandled state: ${unreachable}`);
      }
    }
  };
  render(Object.freeze({ phase: phases.idle }));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const controller = new AbortController();
    const abort = () => controller.abort();
    try {
      const args = [form.id];
      /** @type {string[]} */
      let requestArgs = [];
      for (const [name, value] of new FormData(form)) {
        if (typeof value !== "string") throw new NativeError("Expected a text argument");
        if (name === "request-args") {
          const values = JSON.parse(value);
          if (!Array.isArray(values) || !values.every((value) => typeof value === "string")) {
            throw new NativeError("Request arguments must be a JSON array of strings");
          }
          requestArgs = values;
        } else if (value !== "") args.push(`--${name}`, value);
      }
      args.push(...requestArgs);
      cancel.addEventListener("click", abort);
      window.addEventListener("pagehide", abort);
      await invoke(args, render, controller.signal);
    } catch (error) {
      if (!controller.signal.aborted)
        render(
          Object.freeze({
            phase: phases.failed,
            error: error instanceof Error ? error : new NativeError("Unknown native failure"),
          }),
        );
    } finally {
      cancel.removeEventListener("click", abort);
      window.removeEventListener("pagehide", abort);
    }
  });
}
