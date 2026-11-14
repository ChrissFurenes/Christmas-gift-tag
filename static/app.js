'use strict';
document.querySelectorAll('[data-toggle-target]').forEach(button => {
  button.addEventListener('click', () => {
    const target = document.getElementById(button.dataset.toggleTarget);
    if (!target) return;
    target.hidden = !target.hidden;
    button.setAttribute('aria-expanded', String(!target.hidden));
    button.textContent = target.hidden ? '👁 Vis privat beskrivelse / notat' : '🙈 Skjul privat beskrivelse / notat';
  });
});
document.querySelectorAll('[data-toggle-password]').forEach(button => {
  button.addEventListener('click', () => {
    const field = button.closest('.password-row')?.querySelector('[data-password-field]');
    if (!field) return;
    field.type = field.type === 'password' ? 'text' : 'password';
    button.setAttribute('aria-label', field.type === 'password' ? 'Vis passord' : 'Skjul passord');
  });
});
document.querySelectorAll('[data-date-input]').forEach(input => {
  const panel = input.closest('form')?.querySelector('[data-date-options]');
  if (!panel) return;
  const update = () => {
    panel.hidden = !input.value;
    panel.querySelectorAll('input').forEach(checkbox => { checkbox.disabled = !input.value; });
  };
  input.addEventListener('change', update); input.addEventListener('input', update); update();
});
const dialog = document.getElementById('gift-preview');
document.querySelectorAll('[data-show-preview]').forEach(button => {
  button.addEventListener('click', () => {
    const form = button.closest('[data-gift-form]');
    if (!form || !dialog) return;
    const get = name => form.querySelector(`[name="${name}"]`)?.value || '';
    dialog.querySelector('[data-preview-recipient]').textContent = get('recipient') || '…';
    dialog.querySelector('[data-preview-sender]').textContent = get('sender') || '…';
    const message = dialog.querySelector('[data-preview-message]');
    message.textContent = get('message'); message.hidden = !get('message');
    dialog.showModal();
  });
});
document.querySelectorAll('[data-close-preview]').forEach(button => button.addEventListener('click', () => dialog?.close()));
document.querySelectorAll('[data-confirm]').forEach(form => form.addEventListener('submit', event => {
  if (!window.confirm(form.dataset.confirm)) event.preventDefault();
}));

// Date is pre-filled for new gifts. Removing it disables date-specific rules.
document.querySelectorAll('[data-clear-date]').forEach(button => button.addEventListener('click', () => {
  const input = button.closest('.date-input-block')?.querySelector('[data-date-input]');
  if (input) { input.value = ''; input.dispatchEvent(new Event('input', {bubbles:true})); }
}));
document.querySelectorAll('[data-reset-date]').forEach(button => button.addEventListener('click', () => {
  const input = button.closest('.date-input-block')?.querySelector('[data-date-input]');
  if (input) { input.value = input.dataset.defaultDate || ''; input.dispatchEvent(new Event('input', {bubbles:true})); }
}));
// Filter only the currently logged-in user's labels (all already on this page).
document.querySelectorAll('[data-label-search]').forEach(input => {
  const rows = Array.from(document.querySelectorAll('[data-label-row]'));
  const count = document.querySelector('[data-label-count]');
  const empty = document.querySelector('[data-label-no-match]');
  const update = () => {
    const search = input.value.trim().toLocaleLowerCase('nb-NO');
    let visible = 0;
    rows.forEach(row => {
      const matching = (row.dataset.search || '').toLocaleLowerCase('nb-NO').includes(search);
      row.hidden = !matching;
      if (matching) visible++;
    });
    if (count) count.textContent = String(visible);
    if (empty) empty.hidden = !search || visible !== 0;
  };
  input.addEventListener('input',update);
});
// Passwords are intentionally NOT present in owner dashboard HTML. Fetch only
// after an authenticated owner explicitly presses the reveal button.
document.querySelectorAll('[data-reveal-gift-password]').forEach(button => {
  button.addEventListener('click', async () => {
    const output = document.querySelector(`[data-revealed-password="${button.dataset.revealGiftPassword}"]`);
    if (!output) return;
    if (!output.hidden) {
      output.hidden = true;
      output.textContent = '';
      button.textContent = '👁 Vis gavepassord';
      button.setAttribute('aria-expanded','false');
      return;
    }
    button.disabled = true;
    try {
      const id = encodeURIComponent(button.dataset.revealGiftPassword);
      const response = await fetch(`/admin/gifts/${id}/password`, {credentials:'same-origin',cache:'no-store'});
      if (!response.ok) throw new Error((await response.text()).trim() || 'Ukjent feil');
      const payload = await response.json();
      output.textContent = payload.password;
      output.hidden = false;
      button.textContent = '🙈 Skjul gavepassord';
      button.setAttribute('aria-expanded','true');
    } catch (err) {
      window.alert(err.message || 'Kunne ikke vise gavepassordet.');
    } finally { button.disabled = false; }
  });
});


// Only the current user's gift cards have selection boxes. The server still
// validates ownership of every selected ID when the print form is submitted.
const printForm = document.getElementById('print-selected-form');
if (printForm) {
  const selected = Array.from(document.querySelectorAll('[data-print-select]'));
  const submit = printForm.querySelector('[data-print-submit]');
  const counter = printForm.querySelector('[data-selected-count]');
  const update = () => {
    const count = selected.filter(input => input.checked).length;
    counter.textContent = String(count);
    submit.disabled = count === 0;
  };
  selected.forEach(input => input.addEventListener('change', update));
  document.querySelector('[data-select-visible]')?.addEventListener('click', () => {
    selected.forEach(input => { if (!input.closest('[data-label-row]')?.hidden) input.checked = true; });
    update();
  });
  document.querySelector('[data-clear-selection]')?.addEventListener('click', () => {
    selected.forEach(input => { input.checked = false; });
    update();
  });
  // Opening a new tab submits a normal CSRF-protected form; no JS data fetch.
  printForm.addEventListener('submit', event => {
    if (!selected.some(input => input.checked)) event.preventDefault();
  });
  update();
}
