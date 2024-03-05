const setTheme = function (theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);

    const themeSwitches = document.querySelectorAll('.theme-switch');
    themeSwitches.forEach(switchElement => {
        if (theme === 'light') {
            switchElement.classList.replace('bi-sun-fill', 'bi-moon-stars');
        } else {
            switchElement.classList.replace('bi-moon-stars', 'bi-sun-fill');
        }
    });
}

function reinitializeOffcanvas() {
    const offcanvasElementList = Array.from(document.querySelectorAll('.offcanvas'));

    offcanvasElementList.forEach((offcanvasEl) => {
        const existingInstance = bootstrap.Offcanvas.getInstance(offcanvasEl);
        if (existingInstance) {
            existingInstance.dispose();
        }

        new bootstrap.Offcanvas(offcanvasEl);
    });
}

export function onLoad() {
        const themeSwitches = document.querySelectorAll('.theme-switch');
    themeSwitches.forEach(switchElement => {
        switchElement.addEventListener('click', () => {
            const currentTheme = localStorage.getItem('theme') || 'light';
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            setTheme(newTheme);
        });
    });
}

export function onUpdate() {
    const theme = localStorage.getItem('theme') || 'light';
    setTheme(theme);
    reinitializeOffcanvas();
}

export function onDispose() {

}

