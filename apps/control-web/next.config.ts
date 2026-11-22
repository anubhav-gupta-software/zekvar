import type { NextConfig } from 'next';

const config: NextConfig = {
  poweredByHeader: false,
  outputFileTracingRoot: process.cwd(),
  output: process.env.ZEKVAR_STANDALONE === '1' ? 'standalone' : undefined,
};

export default config;
