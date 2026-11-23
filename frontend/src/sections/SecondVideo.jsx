import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useRef } from 'react';

const SecondVideo = () => {
  const videoRef = useRef(null);

  useGSAP(() => {
    gsap.set('.second-vd-wrapper', { marginTop: '-60vh', opacity: 0 });

    const tl = gsap.timeline({
      scrollTrigger: {
        trigger: '.second-vd-wrapper',
        start: 'top top',
        end: 'bottom top',
        scrub: 2,
        pin: true,
      }
    });

    tl.to('.second-vd-wrapper', { opacity: 1, duration: 1, ease: 'power1.inOut' });

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
    <section className="second-vd-wrapper">
      <div className="h-dvh">
        <video 
          ref={videoRef}
          muted
          playsInline
          preload="auto"
          src="/videos/output2.mp4"
          className="size-full object-cover second-vd"
          style={{ objectPosition: '15% 0%' }}
        />
      </div>
    </section>
  );
};

export default SecondVideo;
