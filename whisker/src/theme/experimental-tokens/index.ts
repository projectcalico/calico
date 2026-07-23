import backgrounds from './background';
import borders from './border';
import customs from './custom';
import elevations from './elevation';
import foregrounds from './foreground';
import links from './link';
import onBackgrounds from './on-background';
import primitives from './primitive';
import categories from './category';

/**
 * The design tokens have been influenced by:
 * - https://designsystem.backbase.com/latest/design-tokens/introduction-5PSH8xS5
 * - https://atlassian.design/foundations/tokens
 */

export default {
    ...primitives,
    ...customs,
    ...borders,
    ...foregrounds,
    ...backgrounds,
    ...elevations,
    ...links,
    ...onBackgrounds,
    ...categories,
};
