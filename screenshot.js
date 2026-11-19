const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1600, height: 1000 },
    deviceScaleFactor: 2
  });

  const filePath = path.resolve(__dirname, 'ddos_dashboard_mockup.html');
  await page.goto(`file://${filePath}`, { waitUntil: 'networkidle' });

  // Wait for charts to render
  await page.waitForTimeout(2000);

  // Take full page screenshot
  await page.screenshot({
    path: 'ddos_dashboard_mockup.png',
    fullPage: true
  });

  console.log('✅ Screenshot saved: ddos_dashboard_mockup.png');

  // Also take viewport-only screenshots of key sections
  const sections = [
    { selector: '.panel:nth-child(1)', name: 'gauges' },
    { selector: '.panel:nth-child(3)', name: 'score_timeline' },
    { selector: '.panel:nth-child(4)', name: 'breakdown' },
    { selector: '.panel:nth-child(5)', name: 'metrics_table' },
    { selector: '.panel:nth-child(6)', name: 'baseline' },
    { selector: '.panel:nth-child(2)', name: 'config_mitigation' }
  ];

  for (const section of sections) {
    try {
      const element = await page.$(section.selector);
      if (element) {
        await element.screenshot({ path: `ddos_dashboard_${section.name}.png` });
        console.log(`✅ Section saved: ddos_dashboard_${section.name}.png`);
      }
    } catch (e) {
      console.log(`⚠️ Section ${section.name} not found`);
    }
  }

  await browser.close();
})();