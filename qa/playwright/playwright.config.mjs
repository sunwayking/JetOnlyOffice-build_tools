import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

const baseURL = process.env.JETONLYOFFICE_QA_BASE_URL;
if (!baseURL) {
  throw new Error('JETONLYOFFICE_QA_BASE_URL is required; report INFRA_INCOMPLETE.');
}

const evidenceDirectory = process.env.JETONLYOFFICE_QA_EVIDENCE_DIR;
if (!evidenceDirectory) {
  throw new Error('JETONLYOFFICE_QA_EVIDENCE_DIR is required; report INFRA_INCOMPLETE.');
}

export default defineConfig({
  testDir: './tests',
  outputDir: path.resolve(evidenceDirectory, 'playwright-output'),
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: [
    ['line'],
    ['json', { outputFile: path.resolve(evidenceDirectory, 'playwright-results.json') }],
    ['html', {
      outputFolder: path.resolve(evidenceDirectory, 'playwright-report'),
      open: 'never',
    }],
  ],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
