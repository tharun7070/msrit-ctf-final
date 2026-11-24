import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { Link } from 'react-router-dom';

const ActII = () => {
  useGSAP(() => {
    gsap.set('.act-ii', { marginTop: '-60vh' });

    gsap.timeline({
      scrollTrigger: {
        trigger: '.act-ii',
        start: 'top 85%',
        end: '15% center',
        scrub: 2,
      }
    });

    gsap.to('.act-ii .img-box', {
      scrollTrigger: {
        trigger: '.act-ii',
        start: 'top center',
        end: '80% center',
        scrub: 1.2,
      },
      y: -250,
      duration: 1,
      ease: 'power1.inOut',
    });
  });

  return (
    <section className="act-section act-ii relative z-10">
      <div className="max-w-xl act-content p-6 sm:p-8 rounded-lg">
        <span className="text-xs font-mono uppercase tracking-widest text-orange-400 font-bold block mb-2">
          TIER TWO // ESCALATION
        </span>
        <h1>ACT II</h1>
        <h2>THE BIG HEIST</h2>
        <p className="mb-4">
          Fleeca vault kiosks. Airport flight network captures. Police department midnight auth records. Repeating XOR broadcasts.
        </p>
        <p className="mb-6">
          The operations get heavier and the surveillance gets tighter. Your crew moves from basic ciphers to live SQL injection simulations, network packet correlation, and Python debugging under pressure. Eight medium-tier contracts paying $100 each — an $800 payout waiting in the city’s core systems.
        </p>

        <div className="pt-2">
          <Link 
            to="/missions" 
            className="btn-outline-heist inline-block py-2.5 px-6 text-xs font-mono font-bold"
          >
            EXPLORE ACT II CONTRACTS →
          </Link>
        </div>

        <div className="act-img-2 mt-12 overflow-hidden rounded border border-orange-500/30">
          <img src="/images/photo1.webp" alt="Fleeca Bank Operation" className="hover:scale-105 transition duration-700" />
        </div>
      </div>

      <div className="space-y-6 mt-60 lg:mt-96 img-box">
        <div className="act-img-1 overflow-hidden rounded border border-orange-500/20">
          <img src="/images/lucia-2.webp" alt="Underground Radio Convoy" className="hover:scale-105 transition duration-700" />
        </div>
        <div className="act-img-3 overflow-hidden rounded border border-orange-500/20">
          <img src="/images/jason-3.webp" alt="Airport Dispatch" className="hover:scale-105 transition duration-700" />
        </div>
      </div>
    </section>
  );
};

export default ActII;
