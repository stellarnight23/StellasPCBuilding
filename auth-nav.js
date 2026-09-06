async function updateAccountLink() {
  const accountLinks = document.querySelectorAll('a[href="auth.html"]');
  if (!accountLinks.length) return;

  try {
    const response = await fetch('/api/me');
    const result = await response.json();
    if (result.user) {
      accountLinks.forEach((link) => {
        link.textContent = result.user.name;
      });
    }
  } catch {
    // The navigation keeps its Account label when the account server is offline.
  }
}

updateAccountLink();
