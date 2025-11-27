/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'bookstore-primary': '#2d5a4d',
        'bookstore-secondary': '#5fe9bc',
        'viridian': {
          500: '#3b7d6e',
          600: '#2f6b5e',
          700: '#24534c',
          800: '#193c38',
          900: '#0f2624',
        },
        'green-btn': '#3b7d6e',
      },

      fontFamily: {
        'sans': ['Prompt', 'sans-serif'],
      },

      boxShadow: {
        'btn-md': '0 4px 6px rgba(0,0,0,0.1)',
        'btn-lg': '0 8px 15px rgba(0,0,0,0.15)',
        'card': '0 2px 12px rgba(0,0,0,0.08)',
      },

      borderRadius: {
        'btn': '12px',
        'card': '16px',
      },

      transitionDuration: {
        400: '400ms',
        600: '600ms',
      },

      transitionTimingFunction: {
        'in-out': 'cubic-bezier(0.4, 0, 0.2, 1)',
      },

      backgroundImage: {
        'btn-gradient': 'linear-gradient(to right, #3b7d6e, #24534c)',
      },

      keyframes: {
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        fadeUp: 'fadeUp 0.8s ease-out forwards',
      },
    },
  },
  plugins: [],
}
