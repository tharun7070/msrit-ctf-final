import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const Hero = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  const isMobile = window.innerWidth < 768;
  const initialMaskPos = isMobile ? 'center 60%' : 'center 55%';
  const initialMaskSize = isMobile ? '30%' : '20%';
  const maskSize = isMobile ? '300%' : '250%';

  useGSAP(() => {
    gsap.set('.mask-wrapper', {
      maskPosition: initialMaskPos,
      maskSize: initialMaskSize,
      WebkitMaskPosition: initialMaskPos,
      WebkitMaskSize: initialMaskSize,
    });

    gsap.set('.mask-logo', { marginTop: '-100vh', opacity: 0 });

    gsap.set('.entrance-message', {
      marginTop: '0vh',
      opacity: 0,
      pointerEvents: 'none',
    });

    const tl = gsap.timeline({
      scrollTrigger: {
        trigger: '.hero-section',
        start: 'top top',
        scrub: 1,
        end: '+=200%',
        pin: true,
      }
    });

    tl
      .to('.fade-out', { opacity: 0, ease: 'power1.inOut' })
      .to('.scale-out', { scale: 1, ease: 'power1.inOut' })
      .to('.mask-wrapper', { maskSize, WebkitMaskSize: maskSize, ease: 'power1.inOut' }, '<')
      .to('.mask-wrapper', { opacity: 0 })
      .to('.overlay-logo', { opacity: 1, onComplete: () => {
        gsap.to('.overlay-logo', { opacity: 0 });
      }}, '<')
      .to('.entrance-message', {
        duration: 1,
        ease: 'power1.inOut',
        opacity: 1,
        pointerEvents: 'auto',
        maskImage: 'radial-gradient(circle at 50% 0vh, black 50%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(circle at 50% 0vh, black 50%, transparent 100%)',
      }, '<');
  });

  return (
    <section className="hero-section">
      <div className="size-full mask-wrapper">
        <img src="/images/hero-bg.webp" alt="background" className="scale-out" />
        <img src="/images/hero-text.webp" alt="hero-logo" className="title-logo fade-out" />
        <button
          className="trailer-logo fade-out btn-heist"
          onClick={() => navigate(user ? '/dashboard' : '/login')}
        >
          ▶ ENTER THE HEIST
        </button>
      </div>

      <div>
        <img src="/images/big-hero-text.svg" alt="logo" className="size-full object-cover mask-logo" />
      </div>

      <div className="fake-logo-wrapper">
        <img src="/images/big-hero-text.svg" className="overlay-logo" alt="FTA overlay" />
      </div>

      <section className="entrance-message">
        <div className="w-full h-full flex flex-col items-center justify-center px-4 py-4 max-h-screen">
          <div className="text-wrapper text-center px-4 max-w-4xl w-full flex flex-col items-center justify-center">
            <span className="text-xs sm:text-sm uppercase font-mono tracking-widest text-cyan font-bold block mb-1 sm:mb-2">
              ● LOS SANTOS UNDERGROUND // CYBER HEIST
            </span>
            <h3 className="gradient-title">FLAG<br />THEFT<br />AUTO</h3>
            <p className="text-pink text-xs sm:text-sm md:text-base tracking-[0.2em] sm:tracking-[0.3em] font-mono mt-2 sm:mt-3">
              LOS SANTOS IS YOUR CIPHER
            </p>
          </div>
        </div>
      </section>
    </section>
  );
};

export default Hero;
