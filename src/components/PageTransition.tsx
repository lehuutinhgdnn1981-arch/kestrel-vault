/**
 * PageTransition wrapper.
 *
 * Wraps route content and applies a smooth fade animation
 * every time the route (location.pathname) changes.
 *
 * Uses CSS animations via Tailwind classes — no framer-motion needed.
 *
 * IMPORTANT: This uses a simple approach — just swap content and
 * apply the enter animation. No fade-out needed because that
 * causes a brief blank gap that looks like "jitter".
 */

import { useLocation } from 'react-router-dom'
import { useEffect, useState, useRef } from 'react'

type TransitionStyle = 'fade-slide' | 'fade-scale' | 'fade-blur'

interface PageTransitionProps {
  children: React.ReactNode
  style?: TransitionStyle
}

export default function PageTransition({ children, style = 'fade-slide' }: PageTransitionProps) {
  const location = useLocation()
  const [displayChildren, setDisplayChildren] = useState(children)
  const [transitioning, setTransitioning] = useState(false)
  const prevPathRef = useRef(location.pathname)

  useEffect(() => {
    if (location.pathname !== prevPathRef.current) {
      prevPathRef.current = location.pathname

      // Start transition: swap content immediately with fade
      setTransitioning(true)
      setDisplayChildren(children)

      // Remove transition state after animation completes
      const timer = setTimeout(() => setTransitioning(false), 200)
      return () => clearTimeout(timer)
    } else {
      setDisplayChildren(children)
      return undefined
    }
  }, [location.pathname, children, style])

  return (
    <div
      className={transitioning ? 'animate-fade-in' : ''}
      style={{ height: '100%', minHeight: '100%' }}
    >
      {displayChildren}
    </div>
  )
}
