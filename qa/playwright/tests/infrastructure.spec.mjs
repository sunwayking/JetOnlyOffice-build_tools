import { test, expect } from '@playwright/test';

test('real DocumentServer QA endpoint is reachable', async ({ request }) => {
  const healthPath = process.env.JETONLYOFFICE_QA_HEALTH_PATH || '/healthcheck';
  const response = await request.get(healthPath);
  expect(response.ok()).toBeTruthy();
});
