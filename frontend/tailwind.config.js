/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#07090e',
          surface: '#0f141d',
          surfaceHover: '#151c28',
          card: '#121824',
          border: '#1f293d',
          borderLight: '#2c3a54',
          muted: '#8b9bb4',
          dim: '#4f5e74',
          accent: '#38bdf8',
        },
        shield: {
          allow: '#10b981',
          allowBg: 'rgba(16, 185, 129, 0.08)',
          allowBorder: 'rgba(16, 185, 129, 0.25)',
          flag: '#f59e0b',
          flagBg: 'rgba(245, 158, 11, 0.08)',
          flagBorder: 'rgba(245, 158, 11, 0.25)',
          quarantine: '#f97316',
          quarantineBg: 'rgba(249, 115, 22, 0.08)',
          quarantineBorder: 'rgba(249, 115, 22, 0.25)',
          block: '#ef4444',
          blockBg: 'rgba(239, 68, 68, 0.08)',
          blockBorder: 'rgba(239, 68, 68, 0.25)',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
