/**
 * Stagger animation hook.
 *
 * Returns an inline style with animation-delay based on the item's index.
 * Used for lists that should animate in one-by-one.
 *
 * Usage:
 *   import { staggerStyle } from '@/hooks/use-stagger'
 *   <div style={staggerStyle(0)}>Item 1</div>
 *   <div style={staggerStyle(1)}>Item 2</div>
 *   <div style={staggerStyle(2)}>Item 3</div>
 */

const STAGGER_DELAY = 40 // ms between each item
const MAX_STAGGER = 20   // cap at 20 items to avoid long delays

export function staggerStyle(index: number): React.CSSProperties {
  const delay = Math.min(index, MAX_STAGGER) * STAGGER_DELAY
  return {
    animationDelay: `${delay}ms`,
  }
}
