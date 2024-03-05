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
}

export function onDispose() {
    
}