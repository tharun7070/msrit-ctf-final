import gsap from 'gsap';
import { useGSAP } from '@gsap/react';

const ActIII = () => {
  useGSAP(() => {
    gsap.set('.act-iii', { marginTop: '-80vh' });

    gsap.timeline({
      scrollTrigger: {
        trigger: '.act-iii',
        start: 'top 80%',
        end: '10% center',
        scrub: 2,
      }
    }).to('.second-vd', { opacity: 0, duration: 1, ease: 'power1.inOut' });

    gsap.to('.act-iii .img-box', {
      scrollTrigger: {
        trigger: '.act-iii',
        start: 'top center',
        end: '80% center',
        scrub: 1.2,
      },
      y: -200,
      duration: 1,
      ease: 'power1.inOut',
    });
  });

  return (
    <section className="act-section act-iii">
      <div className="flex flex-col gap-5 items-end img-box lg:w-1/2 ps-10 mt-96">
        <div className="act-img-1">
          <img src="/images/lucia-1.webp" alt="Fort Zancudo Infiltration" />
        </div>
        <div className="act-img-3">
          <img src="/images/lucia-3.webp" alt="Multi-stage Archive" />
        </div>
      </div>

      <div className="lg:w-1/2 act-content p-6 rounded-lg">
        <div className="max-w-xl lg:ps-32 ps-10">
          <h1>ACT III</h1>
          <h2>THE FINAL GETAWAY</h2>
          <p className="mb-4">
            Fort Zancudo deadbolts. Unsigned JWT bank tokens. Polyglot impound evidence. Recursive freeway routing.
          </p>
          <p>
            The final getaway requires you to dismantle systems that military contractors and bank architects engineered to hold. Five hard missions paying $160 each — an $800 bounty for operators who can finish the job.
          </p>
        </div>

        <div className="act-img-2 mt-8">
          <img src="/images/lucia-2.webp" alt="Mastermind Operative" />
        </div>

        <p className="max-w-xl lg:ps-32 ps-10 mt-8 text-pink text-xl font-bold">
          Crack all 15 jobs across three tiers to claim the maximum $1,550 crew bounty.
        </p>
      </div>
    </section>
  );
};

export default ActIII;
