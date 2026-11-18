for (const input of document.querySelectorAll('input[type="file"]')) input.addEventListener("change", () => {
  input.closest("label").querySelector("output").textContent = input.files[0]?.name || "No file selected";
});
for (const button of document.querySelectorAll(".reveal")) button.addEventListener("click", () => {
  const input = button.parentElement.querySelector("input");
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  button.textContent = visible ? "SHOW" : "HIDE";
  button.setAttribute("aria-label", visible ? "Show password" : "Hide password");
});

