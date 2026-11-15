const sqlToggle = document.querySelector('#sql-toggle');
const authToggle = document.querySelector('#auth-toggle');
const sqlMode = document.querySelector('#sql-mode');
const authMode = document.querySelector('#auth-mode');
const sqlResult = document.querySelector('#sql-result');
const authResult = document.querySelector('#auth-result');
const authStatus = document.querySelector('#auth-status');

function setModeIndicator(element, vulnerable) {
  element.textContent = vulnerable ? 'Ranjivi način rada' : 'Sigurni način rada';
  element.classList.toggle('status-vulnerable', vulnerable);
  element.classList.toggle('status-secure', !vulnerable);
}

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Zahtjev nije uspio.');
  }
  return data;
}

async function refreshAuthStatus() {
  const data = await request('/api/auth/status');
  authStatus.textContent = data.authenticated
    ? `Prijavljeni ste kao ${data.username}.`
    : 'Niste prijavljeni.';
  authToggle.checked = data.mode === 'vulnerable';
  setModeIndicator(authMode, authToggle.checked);
}

sqlToggle.addEventListener('change', async () => {
  try {
    const data = await request('/api/modes/sql-injection/toggle', { method: 'POST' });
    sqlToggle.checked = data.vulnerableMode;
    setModeIndicator(sqlMode, data.vulnerableMode);
  } catch (error) {
    sqlToggle.checked = !sqlToggle.checked;
    sqlResult.textContent = error.message;
  }
});

authToggle.addEventListener('change', async () => {
  try {
    const data = await request('/api/modes/authentication/toggle', { method: 'POST' });
    authToggle.checked = data.vulnerableMode;
    setModeIndicator(authMode, data.vulnerableMode);
    await refreshAuthStatus();
    authResult.textContent = 'Način rada je promijenjen. Postojeća prijava je poništena.';
  } catch (error) {
    authToggle.checked = !authToggle.checked;
    authResult.textContent = error.message;
  }
});

document.querySelector('#sql-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await request('/api/sql-injection/test', {
      method: 'POST',
      body: JSON.stringify({
        username: document.querySelector('#sql-username').value,
        pin: document.querySelector('#sql-pin').value,
      }),
    });
    sqlResult.textContent = JSON.stringify(data.rows, null, 2);
  } catch (error) {
    sqlResult.textContent = error.message;
  }
});

document.querySelector('#auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const data = await request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.querySelector('#auth-username').value,
        password: document.querySelector('#auth-password').value,
      }),
    });
    authResult.textContent = JSON.stringify(data, null, 2);
    await refreshAuthStatus();
  } catch (error) {
    authResult.textContent = error.message;
    await refreshAuthStatus();
  }
});

document.querySelector('#logout').addEventListener('click', async () => {
  try {
    await request('/api/auth/logout', { method: 'POST' });
    authResult.textContent = 'Odjava je uspješna.';
    await refreshAuthStatus();
  } catch (error) {
    authResult.textContent = error.message;
  }
});

refreshAuthStatus().catch((error) => {
  authResult.textContent = error.message;
});
