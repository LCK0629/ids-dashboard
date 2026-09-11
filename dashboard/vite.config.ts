import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

function productionBase() {
  const configuredBase = process.env.VITE_BASE_PATH?.trim();
  if (!configuredBase) return '/ids-dashboard/';

  return `/${configuredBase.replace(/^\/+|\/+$/g, '')}/`;
}

export default defineConfig(({ command, isPreview }) => ({
  base: command === 'build' || isPreview ? productionBase() : '/',
  plugins: [react()],
}));
