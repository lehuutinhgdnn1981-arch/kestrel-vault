/**
 * useStaggerAnimation hook.
 *
 * Returns a CSS animation delay string for staggered list/item animations.
 * Each item fades in slightly after the previous one.
 *
 * @param index - The item's position in the list
 * @param baseDelay - Base delay in ms (default: 50)
 * @param maxDelay - Maximum total stagger delay in ms (default: 500)
 * @returns CSS delay string like "50ms", "100ms", etc.
 *
 * Usage:
 * ```tsx
 * const delay = useStaggerAnimation(index)
 * <div style={{ animationDelay: delay }} className="animate-stagger-in">
 *   {item}
 * </div>
 * ```
 */

import { useMemo } from 'react'

export function useStaggerDelay(index: number, baseDelay = 50, maxDelay = 500): string {
  return useMemo(() => {
    const delay = Math.min(index * baseDelay, maxDelay)
    return `${delay}ms`
  }, [index, baseDelay, maxDelay])
}

/**
 * Generates inline styles for stagger animation.
 * Includes opacity: 0 initially so items are hidden before animation starts.
 */
export function staggerStyle(index: number, baseDelay = 50, maxDelay = 500): React.CSSProperties {
  const delay = Math.min(index * baseDelay, maxDelay)
  return {
    animationDelay: `${delay}ms`,
    animationFillMode: 'both',
    opacity: 0, // hidden until animation starts
  }
}
