import { useEffect, useRef, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../app/auth';

const TOTAL_FRAMES = 240;
const FPS = 30;
const FRAME_INTERVAL = 1000 / FPS;

function useFramePlayer(canvasRef) {
  const framesRef = useRef([]);
  const exactFrameRef = useRef(0);
  const rafRef = useRef(null);
  const lastTimeRef = useRef(0);
  const scrollVelocityRef = useRef(0);
  const lastScrollYRef = useRef(typeof window !== 'undefined' ? window.scrollY : 0);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const images = [];

    const loadFrame = (i) =>
      new Promise((resolve) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => resolve(null);
        img.src = `/hero-frames/frame_${String(i).padStart(4, '0')}.jpg`;
      });

    async function preload() {
      // Load first 30 frames immediately for fast start
      const firstBatch = [];
      for (let i = 1; i <= Math.min(30, TOTAL_FRAMES); i++) {
        firstBatch.push(loadFrame(i));
      }
      const first = await Promise.all(firstBatch);
      if (cancelled) return;
      first.forEach((img, idx) => { images[idx] = img; });
      framesRef.current = images;
      setIsLoaded(true);

      // Load rest in background
      for (let i = 31; i <= TOTAL_FRAMES; i++) {
        if (cancelled) return;
        const img = await loadFrame(i);
        images[i - 1] = img;
      }
      framesRef.current = images;
    }

    preload();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      const delta = currentScrollY - lastScrollYRef.current;
      lastScrollYRef.current = currentScrollY;

      // Update velocity based on scroll delta
      // Positive delta (scroll down) = fast forward
      // Negative delta (scroll up) = fast rewind
      scrollVelocityRef.current += delta * 0.15;
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (!isLoaded) return;

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function tick(timestamp) {
      if (!lastTimeRef.current) lastTimeRef.current = timestamp;
      const deltaMs = timestamp - lastTimeRef.current;
      lastTimeRef.current = timestamp;

      // Base idle speed: 18 fps
      const baseFps = 18;
      const currentFps = baseFps + scrollVelocityRef.current;

      // Add friction to gradually bring velocity back to 0
      scrollVelocityRef.current *= 0.92;

      // Advance frames based on current FPS and time delta
      const framesToAdvance = currentFps * (deltaMs / 1000);
      const framesCount = framesRef.current.length;

      exactFrameRef.current = (exactFrameRef.current + framesToAdvance) % framesCount;
      if (exactFrameRef.current < 0) {
        exactFrameRef.current += framesCount; // Handle backward looping
      }

      const currentIdx = Math.floor(exactFrameRef.current);
      const img = framesRef.current[currentIdx];

      if (img && img.naturalWidth > 0) {
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
        ctx.drawImage(img, 0, 0);
      }

      rafRef.current = requestAnimationFrame(tick);
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [isLoaded, canvasRef]);

  return isLoaded;
}

const features = [
  {
    icon: '🛡️',
    title: 'Vulnerability Detection',
    description: 'Deep automated scanning that catches OWASP Top 10, misconfigurations, and zero-day patterns.',
  },
  {
    icon: '✨',
    title: 'Automated Code Healing',
    description: 'Scans your codebase, generates precise fixes, deploys with your approval.',
  },
  {
    icon: '📡',
    title: 'Continuous Monitoring',
    description: 'Always-on surveillance of your attack surface with instant alerts on new threats.',
  },
  {
    icon: '📊',
    title: 'Actionable Reports',
    description: 'Clear, prioritized findings with step-by-step remediation guidance your team can act on.',
  },
];

const metrics = [
  { value: '500+', label: 'Scans completed' },
  { value: '<2s', label: 'Median scan time' },
  { value: '99.9%', label: 'Uptime' },
];

function getEntryRoute(auth) {
  return auth.isAdmin ? '/admin/dashboard' : '/dashboard';
}

export function HomePage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const canvasRef = useRef(null);
  const heroWrapRef = useRef(null);
  const [navScrolled, setNavScrolled] = useState(false);

  const entryRoute = getEntryRoute(auth);
  const primaryRoute = auth.isAuthenticated ? entryRoute : '/login';

  const isLoaded = useFramePlayer(canvasRef);

  // Mouse parallax effect for hero background
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!heroWrapRef.current) return;
      const { innerWidth, innerHeight } = window;
      const x = (e.clientX / innerWidth) * 2 - 1;
      const y = (e.clientY / innerHeight) * 2 - 1;
      
      const moveX = x * -25;
      const moveY = y * -25;

      heroWrapRef.current.style.transform = `scale(1.05) translate(${moveX}px, ${moveY}px)`;
    };
    
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  useEffect(() => {
    const handleScroll = () => setNavScrolled(window.scrollY > 10);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleStartClick = useCallback(() => navigate(primaryRoute), [navigate, primaryRoute]);

  return (
    <div className="apple-home">
      {/* ─── Sticky Nav ─── */}
      <nav className={`apple-nav${navScrolled ? ' scrolled' : ''}`}>
        <div className="apple-nav-inner">
          <Link to="/" className="apple-wordmark">AEGIS AI</Link>

          <div className="apple-nav-links">
            <a href="#capabilities">Capabilities</a>
            <a href="#performance">Performance</a>
          </div>

          <div className="apple-nav-actions">
            <Link
              className="apple-btn apple-btn--ghost"
              to={auth.isAuthenticated ? entryRoute : '/login'}
            >
              {auth.isAuthenticated ? 'Dashboard' : 'Sign In'}
            </Link>
            <Link
              className="apple-btn apple-btn--primary"
              to={auth.isAuthenticated ? '/projects/new' : '/register'}
            >
              {auth.isAuthenticated ? 'New Project' : 'Get Started'}
            </Link>
          </div>
        </div>
      </nav>

      {/* ─── Hero ─── */}
      <section className="apple-hero">
        <div 
          ref={heroWrapRef}
          className="apple-hero-video-wrap"
          style={{ transition: 'transform 0.6s cubic-bezier(0.2, 0.8, 0.2, 1)' }}
        >
          <canvas
            ref={canvasRef}
            className={`apple-hero-canvas${isLoaded ? ' visible' : ''}`}
          />
          <div className="apple-hero-overlay" />
        </div>

        <div className="apple-hero-content">
          <p className="apple-hero-kicker">Security scanner for modern SaaS</p>
          <h1 className="apple-hero-title">
            Hackers don't wait.<br />
            Neither do we. 
          </h1>
          <p className="apple-hero-subtitle">
            We don’t just find bugs. We fix them for you — with enterprise-grade scanning, continuous monitoring, and clear remediation, all in one powerful workspace.
          </p>

          <div className="apple-hero-actions">
            <button
              className="apple-btn apple-btn--hero-primary"
              type="button"
              onClick={handleStartClick}
            >
              {auth.isAuthenticated ? 'Open Dashboard' : 'Start for Free'}
            </button>
            <Link
              className="apple-btn apple-btn--hero-secondary"
              to={auth.isAuthenticated ? entryRoute : '/register'}
            >
              {auth.isAuthenticated ? 'View Workspace' : 'Create Account'}
            </Link>
          </div>
        </div>
      </section>

      {/* ─── Metrics Ribbon ─── */}
      <section className="apple-metrics" id="performance">
        <div className="apple-metrics-inner">
          {metrics.map((m) => (
            <div key={m.label} className="apple-metric">
              <span className="apple-metric-value">{m.value}</span>
              <span className="apple-metric-label">{m.label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Features ─── */}
      <section className="apple-features" id="capabilities">
        <div className="apple-section-inner">
          <p className="apple-section-kicker">Capabilities</p>
          <h2 className="apple-section-title">Everything you need, nothing you don't.</h2>

          <div className="apple-features-grid">
            {features.map((f) => (
              <div key={f.title} className="apple-feature-card">
                <span className="apple-feature-icon">{f.icon}</span>
                <h3>{f.title}</h3>
                <p>{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── CTA ─── */}
      <section className="apple-cta">
        <div className="apple-section-inner apple-cta-inner">
          <h2>Ready to ship safer code?</h2>
          <button
            className="apple-btn apple-btn--hero-primary"
            type="button"
            onClick={handleStartClick}
          >
            {auth.isAuthenticated ? 'Go to Dashboard' : 'Get Started'}
          </button>
        </div>
      </section>

      {/* ─── Footer ─── */}
      <footer className="apple-footer">
        <div className="apple-footer-inner">
          <span className="apple-wordmark">AEGIS AI</span>
          <span className="apple-footer-copy">&copy; {new Date().getFullYear()} AEGIS AI. All rights reserved.</span>
        </div>
      </footer>
    </div>
  );
}
