import { useGSAP } from '@gsap/react';
import gsap from 'gsap';
import { useRef } from 'react';

const Final = () => {
  const videoRef = useRef(null);

  useGSAP(() => {
    gsap.set('.final-content', { opacity: 0 });

    const tl = gsap.timeline({ 
      scrollTrigger: {
        trigger: '.final',
        start: 'top top',
        end: '+=100% top',
        scrub: true,
        pin: true,
      }
    });

    tl.to('.final-content', { opacity: 1, duration: 1, scale: 1, ease: 'power1.inOut' });

    const video = videoRef.current;
    if (video) {
      const attachScrub = () => {
        if (video.duration && !isNaN(video.duration)) {
          tl.to(video, { currentTime: video.duration, duration: 3, ease: 'none' }, '<');
        }
      };
      if (video.readyState >= 1) {
        attachScrub();
      } else {
        video.addEventListener('loadedmetadata', attachScrub, { once: true });
      }
    }
  });

  return (
    <section className="final">
      <div className="final-content size-full">
        <video 
          ref={videoRef}
          muted
          playsInline
          preload="auto"
          src="/videos/output3.mp4"
          className="size-full object-cover"
        />
      </div>
    </section>
  );
};

export default Final;
