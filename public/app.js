const form = document.querySelector("#pair-form");
const status = document.querySelector("#status");
const buttons = [...form.querySelectorAll("button")];

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  const email = form.elements.email.value.trim();

  status.className = "status";
  status.textContent = "Sending confirmation…";
  buttons.forEach((button) => { button.disabled = true; });

  try {
    const response = await fetch("/api/request-verification", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, action: submitter.dataset.action }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Something went wrong.");

    status.textContent = result.message;
    if (result.verificationUrl) {
      status.append(" ");
      const link = document.createElement("a");
      link.href = result.verificationUrl;
      link.textContent = "Open local confirmation";
      status.append(link);
    }
    form.reset();
  } catch (error) {
    status.className = "status error";
    status.textContent = error instanceof Error ? error.message : "Something went wrong.";
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
});
