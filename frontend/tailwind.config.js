/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#e9efe9',
          surface: '#e5ece5',
          surfaceHover: '#dfe9e0',
          card: '#f4f6f2',
          border: '#cbd7cc',
          borderLight: '#9eafa2',
          muted: '#4d6358',
          dim: '#74877a',
          accent: '#293f35',
          cyan: '#467f81',
        },
        shield: {
          allow: '#3e704f',
          allowBg: 'rgba(62, 112, 79, 0.10)',
          allowBorder: 'rgba(62, 112, 79, 0.30)',
          flag: '#94661c',
          flagBg: 'rgba(148, 102, 28, 0.10)',
          flagBorder: 'rgba(148, 102, 28, 0.30)',
          quarantine: '#a56236',
          quarantineBg: 'rgba(165, 98, 54, 0.10)',
          quarantineBorder: 'rgba(165, 98, 54, 0.30)',
          block: '#a64d44',
          blockBg: 'rgba(166, 77, 68, 0.10)',
          blockBorder: 'rgba(166, 77, 68, 0.30)',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
        sans: ['system-ui', 'Segoe UI', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
