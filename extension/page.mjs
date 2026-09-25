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
    try {
      const args = [form.id];
      const data = new FormData(form);
      for (const [name, value] of data) {
        if (typeof value !== "string") throw new NativeError("Expected a text argument");
        if (name !== "request-args" && value !== "") args.push(`--${name}`, value);
      }
      const request = data.get("request-args");
      if (request !== null) {
        if (typeof request !== "string") throw new NativeError("Expected request arguments");
        const values = JSON.parse(request);
        if (!Array.isArray(values) || !values.every((value) => typeof value === "string")) {
          throw new NativeError("Request arguments must be a JSON array of strings");
        }
        args.push(...values);
      }
      cancel.addEventListener("click", abort, { once: true });
      window.addEventListener("pagehide", abort, { once: true });
      fields.disabled = true;
      cancel.disabled = false;
      output.textContent = "Running…";
      const result = await invoke(
        args,
        (address) => {
          output.textContent = `Ready: ${address}. Waiting for one attestation.`;
        },
        controller.signal,
      );
      if ("stdout_base64" in result && typeof result.stdout_base64 === "string") {
        const bytes = Uint8Array.from(atob(result.stdout_base64), (byte) => byte.charCodeAt(0));
        output.textContent = new TextDecoder().decode(bytes);
      } else {
        output.textContent = `Completed\n${JSON.stringify(result, null, 2)}`;
      }
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
