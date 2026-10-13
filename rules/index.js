// Fingerprints live in JSON so they can be reviewed and tested without touching engine code.
// Each rule: { name, categories, source, header?, pattern, confidence, version?, showValue?, examples }.
import frameworks from './frameworks.json' with { type: 'json' };
import libraries from './libraries.json' with { type: 'json' };
import analytics from './analytics.json' with { type: 'json' };
import platforms from './platforms.json' with { type: 'json' };
import headers from './headers.json' with { type: 'json' };

export const RULES = Object.freeze([
  ...frameworks,
  ...libraries,
  ...analytics,
  ...platforms,
  ...headers,
]);
