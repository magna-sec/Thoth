// Filter a chip-cloud: an <input data-cloud="targetId"> hides non-matching chips.
(function () {
  document.querySelectorAll('[data-cloud]').forEach((input) => {
    const target = document.getElementById(input.dataset.cloud);
    if (!target) return;
    input.addEventListener('input', () => {
      const q = input.value.trim().toLowerCase();
      target.querySelectorAll('.chip').forEach((chip) => {
        chip.hidden = q !== '' && !chip.textContent.toLowerCase().includes(q);
      });
    });
  });
})();
