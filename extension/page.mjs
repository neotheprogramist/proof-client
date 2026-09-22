// @ts-check
import { invoke, NativeError } from "./native.mjs";
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
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const controller = new AbortController();
    const abort = () => controller.abort();
    cancel.addEventListener("click", abort, { once: true });
    window.addEventListener("pagehide", abort, { once: true });
    const args = [form.id];
    for (const input of form.querySelectorAll("input")) {
      if (input.value !== "") args.push(`--${input.name}`, input.value);
    }
    fields.disabled = true;
    cancel.disabled = false;
    output.textContent = "Running…";
    try {
      const result = await invoke(
        args,
        (address) => {
          output.textContent = `Ready: ${address}. Waiting for one attestation.`;
        },
        controller.signal,
      );
      output.textContent = `Completed\n${JSON.stringify(result, null, 2)}`;
    } catch (error) {
      output.textContent = `Failed: ${error instanceof Error ? error.message : "Unknown native failure"}`;
    } finally {
      fields.disabled = false;
      cancel.disabled = true;
      cancel.removeEventListener("click", abort);
      window.removeEventListener("pagehide", abort);
    }
  });
}
