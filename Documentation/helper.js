document.addEventListener("DOMContentLoaded", () => {
  const qp = new URLSearchParams(document.location.search);
  const darkMode = (() => {
    const s = qp.get("dark-mode");
    if (s == null) {
      return false;
    }
    const lower = s.toLowerCase();
    if (["true", "false", "yes", "no", "y", "n"].includes(lower)) {
      return ["true", "yes", "y"].includes(lower);
    }
    const num = +s;
    if (!isNaN(num)) {
      return num !== 0;
    }
    return false;
  })();
  const baseUrl = new URL(document.location);
  [...document.getElementsByTagName("a")].forEach((anchor) => {
    try {
      const url = new URL(anchor.href);
      if (url.origin === baseUrl.origin) {
        url.searchParams.set("dark-mode", darkMode ? "1" : "0");
        anchor.href = url.toString();
      }
    } catch (exc) {
      console.warn(exc);
    }
  });
  if (darkMode) {
    document.body.classList.add("dark-mode");
  } else {
    document.body.classList.remove("dark-mode");
  }
});
