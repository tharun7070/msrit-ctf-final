import gsap from 'gsap';
import { useGSAP } from '@gsap/react';

const ActI = () => {
  useGSAP(() => {
    gsap.set('.act-i', { marginTop: '-80vh' });

    gsap.timeline({
      scrollTrigger: {
        trigger: '.act-i',
        start: 'top 90%',
        end: '10% center',
        scrub: 2,
      }
    }).to('.first-vd', { opacity: 0, duration: 1, ease: 'power1.inOut' });

    gsap.to('.act-i .img-box', {
      scrollTrigger: {
        trigger: '.act-i',
        start: 'top center',
        end: '80% center',
        scrub: 1.2,
      },
      y: -300,
      duration: 1,
      ease: 'power1.inOut',
    });
  });

  return (
    <section className="act-section act-i">
      <div className="max-w-lg act-content p-6 rounded-lg">
        <h1>ACT I</h1>
        <h2>THE STREET JOB</h2>
        <p className="mb-4">
          Five starter jobs. First blood. Build your credentials in the Los Santos underground.
        </p>
        <p>
          Your crew intercepts courier signals, cracks rotation ciphers, digs through hidden drop manifests, and extracts sensitive payloads from image metadata. Five jobs worth $50 each — $250 waiting on the street.
        </p>

        <div className="act-img-2 mt-12">
          <img src="/images/jason-2.webp" alt="Street Operative" />
        </div>
      </div>

      <div className="space-y-5 mt-96 img-box">
        <div className="act-img-1">
          <img src="/images/jason-1.webp" alt="Lester Dispatch" />
        </div>
        <div className="act-img-3">
          <img src="/images/jason-3.webp" alt="Sandy Shores Stash" />
        </div>
      </div>
    </section>
  );
};

export default ActI;
