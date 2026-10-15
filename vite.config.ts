import react from '@vitejs/plugin-react';
import {defineConfig} from 'vite';

export default defineConfig({
  plugins:[react()],
  build:{outDir:'dist/client'},
  server:{port:5178,proxy:{'/api':{target:'http://localhost:8797',ws:true}}},
});
