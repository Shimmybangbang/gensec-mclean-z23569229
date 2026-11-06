  const $ = (id) => document.getElementById(id);

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", t === tab));
      $("panel-encode").hidden = tab.dataset.tab !== "encode";
      $("panel-decode").hidden = tab.dataset.tab !== "decode";
    });
  });

  function showMessage(container, text, kind) {
    const div = document.createElement("div");
    div.className = "msg " + kind;
    div.textContent = text;
    container.replaceChildren(div);
  }

  async function post(url, form, button) {
    button.disabled = true;
    try {
      const res = await fetch(url, { method: "POST", body: new FormData(form) });
      const data = await res.json().catch(() => ({ error: "Unexpected server response." }));
      if (!res.ok) throw new Error(data.error || "Something went wrong.");
      return data;
    } finally {
      button.disabled = false;
    }
  }

  let capacity = null;
  function updateCount() {
    const n = new TextEncoder().encode($("enc-message").value).length;
    if (capacity == null) { $("enc-count").textContent = `${n} bytes`; return; }
    const covert = $("enc-password").value !== "";
    const max = covert ? capacity.covert_capacity : capacity.capacity;
    $("enc-count").textContent = `${n} / ${max.toLocaleString()} bytes` +
      (covert ? " — password set: encrypted, scattered, no signature"
              : " — no password: anyone can detect and read this");
  }
  $("enc-message").addEventListener("input", updateCount);
  $("enc-password").addEventListener("input", updateCount);

  $("enc-image").addEventListener("change", async () => {
    capacity = null; $("enc-capacity").textContent = ""; updateCount();
    if (!$("enc-image").files.length) return;
    const fd = new FormData(); fd.append("image", $("enc-image").files[0]);
    const res = await fetch("/api/capacity", { method: "POST", body: fd });
    const data = await res.json();
    if (res.ok) {
      capacity = data;
      $("enc-capacity").textContent =
        `${data.width}×${data.height} — holds about ${data.covert_capacity.toLocaleString()} bytes ` +
        `with a password, ${data.capacity.toLocaleString()} without`;
    } else {
      $("enc-capacity").textContent = data.error;
    }
    updateCount();
  });

  $("encode-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = $("enc-result");
    try {
      const data = await post("/api/encode", e.target, e.submitter);
      const base = ($("enc-image").files[0].name.replace(/\.[^.]+$/, "") || "image") + "-stego.png";
      const wrap = document.createElement("div"); wrap.className = "preview";
      const ok = document.createElement("div"); ok.className = "msg ok"; ok.textContent = "Message hidden.";
      const img = document.createElement("img"); img.src = data.image; img.alt = "Image with hidden message";
      const a = document.createElement("a"); a.href = data.image; a.download = base; a.textContent = "Download " + base;
      wrap.append(ok, img, a);
      out.replaceChildren(wrap);
    } catch (err) { showMessage(out, err.message, "error"); }
  });

  $("decode-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const data = await post("/api/decode", e.target, e.submitter);
      showMessage($("dec-result"), data.message, "ok");
    } catch (err) { showMessage($("dec-result"), err.message, "error"); }
  });
