/**
 * SecureVault Client-side Helpers
 * Security-focused UX enhancements & clipboard handling
 */

document.addEventListener("DOMContentLoaded", () => {
    // Copy to clipboard helper
    const copyBtns = document.querySelectorAll(".btn-copy");
    copyBtns.forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const textToCopy = btn.getAttribute("data-copy-text");
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = btn.innerHTML;
                    btn.innerHTML = "✓ Copied!";
                    btn.classList.add("btn-primary");
                    setTimeout(() => {
                        btn.innerHTML = originalText;
                        btn.classList.remove("btn-primary");
                    }, 2000);
                }).catch(err => {
                    console.error("Clipboard copy failed:", err);
                });
            }
        });
    });

    // Auto-dismiss alert boxes after 6 seconds
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = "opacity 0.5s ease";
            alert.style.opacity = "0";
            setTimeout(() => alert.remove(), 500);
        }, 6000);
    });
});

// Modal helpers
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.style.display = "flex";
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.style.display = "none";
}
