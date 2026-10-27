import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-anamorphic/',
  build: {
    target: 'es2022',
    sourcemap: true,
  },
});
