import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useRef } from 'react';

const FirstVideo = () => {
  const videoRef = useRef(null);

  useGSAP(() => {
    gsap.set('.first-vd-wrapper', { marginTop: '-150vh', opacity: 0 });

    const tl = gsap.timeline({
      scrollTrigger: {
        trigger: '.first-vd-wrapper',
        start: 'top top',
        end: '+=200% top',
        scrub: true,
        pin: true,
      }
    });

    tl.to('.hero-section', { delay: 0.5, opacity: 0, ease: 'power1.inOut' });
    tl.to('.first-vd-wrapper', { opacity: 1, duration: 2, ease: 'power1.inOut' });

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
  }, []);

  return (
    <section className="first-vd-wrapper">
      <div className="h-dvh">
        <video 
          ref={videoRef}
          muted
          playsInline
          preload="auto"
          src="/videos/output1.mp4"
          className="first-vd"
        />
      </div>
    </section>
  );
};

export default FirstVideo;
