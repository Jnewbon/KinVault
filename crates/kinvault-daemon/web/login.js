"use strict";

const form = document.getElementById("login");
const error = document.getElementById("error");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  error.hidden = true;
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-KinVault": "1" },
      body: JSON.stringify({ password: document.getElementById("password").value }),
    });
    if (res.ok) {
      location.reload();
      return;
    }
    error.textContent = (await res.text()) || "Sign-in failed.";
  } catch (err) {
    error.textContent = "Can't reach the KinVault server.";
  }
  error.hidden = false;
  button.disabled = false;
});
