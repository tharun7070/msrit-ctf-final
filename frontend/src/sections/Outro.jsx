import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { Link, useNavigate } from 'react-router-dom';

const Outro = () => {
  const navigate = useNavigate();

  useGSAP(() => {
    gsap.set('.final-message', { marginTop: '-100vh', opacity: 0 });

    const tl = gsap.timeline({
      scrollTrigger: {
        trigger: '.final-message',
        start: 'top 30%',
        end: 'top 10%',
        scrub: true,
      }
    });

    tl.to('.final-content', { opacity: 0, duration: 1, ease: 'power1.inOut' });
    tl.to('.final-message', { opacity: 1, duration: 1, ease: 'power1.inOut' });
  });

  return (
    <section className="final-message relative z-50 pointer-events-auto">
      <div className="h-full col-center gap-8 px-6 text-center relative z-50 pointer-events-auto">
        <img src="/images/logo.webp" alt="FTA Logo" className="md:w-64 w-44" />

        <div>
          <h3 className="gradient-title">
            YOUR CREW.<br />YOUR HEIST.<br />YOUR LEGACY.
          </h3>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl w-full my-4">
          <div className="hud-panel p-4 rounded text-center">
            <span className="block text-cash font-bold text-2xl md:text-3xl">15</span>
            <span className="text-xs uppercase text-gray-400">Total Missions</span>
          </div>
          <div className="hud-panel p-4 rounded text-center">
            <span className="block text-cash font-bold text-2xl md:text-3xl">$1,550</span>
            <span className="text-xs uppercase text-gray-400">Max Bounty</span>
          </div>
          <div className="hud-panel p-4 rounded text-center">
            <span className="block text-cash font-bold text-2xl md:text-3xl">150m</span>
            <span className="text-xs uppercase text-gray-400">Time Limit</span>
          </div>
          <div className="hud-panel p-4 rounded text-center">
            <span className="block text-cash font-bold text-2xl md:text-3xl">2–3</span>
            <span className="text-xs uppercase text-gray-400">Crew Size</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-4 justify-center items-center relative z-50">
          <Link 
            to="/register"
            className="btn-heist text-lg py-3 px-8 cursor-pointer relative z-50 inline-block pointer-events-auto"
          >
            ▶ JOIN THE HEIST
          </Link>
          <Link 
            to="/leaderboard"
            className="btn-outline-heist text-lg py-3 px-8 cursor-pointer relative z-50 inline-block pointer-events-auto"
          >
            LIVE LEADERBOARD ↗
          </Link>
        </div>

        <footer className="mt-8 text-xs text-gray-500 font-mono">
          FLAG THEFT AUTO // SECURE CTF PLATFORM // ALL EVIDENCE FICTIONAL & AUTHORIZED
        </footer>
      </div>
    </section>
  );
};

export default Outro;
