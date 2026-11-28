// Round-trip the writer's emitted surface through the existing spatial renderer.
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {join, resolve} from 'node:path';

const root = resolve(process.argv[2]);
const {withBrowser} = await import(pathToFileURL(join(root, 'test-support/browser.js')));
let input = '';
for await (const chunk of process.stdin) input += chunk;
const messages = JSON.parse(input);

await withBrowser(async (browser, origin) => {
  const page = await browser.newPage();
  await page.goto(origin + '/test-support/spatial-hud-host.html');
  const event = await page.evaluate(messages => {
    const {createSpatialHud} = window.spatialHud;
    const mount = document.body.appendChild(document.createElement('div'));
    const actions = [];
    const hud = createSpatialHud({
      document, parent: new window.three.Group(), accessibilityRoot: mount,
      send: envelope => actions.push(envelope.action),
    });
    for (const message of messages) hud.receive(message);
    hud.update();
    const button = mount.querySelector('button[aria-label="Take card"]');
    if (!button || button.disabled) throw Error('The selected card is not actionable');
    button.click();
    if (actions.length !== 1) throw Error('Expected one user action');
    const {surfaceId, name, context} = actions[0];
    return {surfaceId, name, context};
  }, messages);
  assert.equal(event.name, 'claim');
  process.stdout.write('\nDAIMON_CARDS_EVENT ' + JSON.stringify(event) + '\n');
}, root);
