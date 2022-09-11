{
  const toBool = (s) => {
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
  };
  const getByIdOrCreate = (id, create) => {
    const elem = document.getElementById(id);
    if (elem != null) {
      return elem;
    }
    return create();
  };
  const reflectDarkMode = () => {
    const qp = new URLSearchParams(document.location.search);
    const darkMode = toBool(qp.get("dark-mode"));
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
  };
  (async () => {
    await (window.linkHelperCompleted ??
      new Promise((resolve) =>
        document.addEventListener("DOMContentLoaded", () => resolve())
      ));
    reflectDarkMode();
    const toggle = getByIdOrCreate("dark-mode-toggle", () => {
      const btn = document.createElement("button");
      btn.innerText = "Toggle Dark Mode";
      btn.setAttribute("id", "dark-mode-toggle");
      const h1s = document.getElementsByTagName("h1");
      if (h1s.length) {
        h1s[0].insertAdjacentElement("afterend", document.createElement("br"));
        h1s[0].insertAdjacentElement("afterend", btn);
      } else {
        document.body.insertAdjacentElement(
          "afterbegin",
          document.createElement("br")
        );
        document.body.insertAdjacentElement("afterbegin", btn);
      }
      return btn;
    });
    toggle.addEventListener("click", () => {
      const url = new URL(document.location);
      url.searchParams.set(
        "dark-mode",
        toBool(url.searchParams.get("dark-mode")) ? "0" : "1"
      );
      document.location.replace(url.toString());
      reflectDarkMode();
    });
  })();
}
