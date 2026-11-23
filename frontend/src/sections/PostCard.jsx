import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';

const PostCard = () => {
  const videoRef = useRef(null);
  const navigate = useNavigate();

  useGSAP(() => {
    gsap.timeline({
      scrollTrigger: {
        trigger: '.post-card',
        start: 'top center',
        end: 'bottom center',
        scrub: 1,
      }
    });
  });

  return (
    <section className="post-card">
      <div className="animated-gradient-bg" />

      <div className="post-card-wrapper group hover:rotate-1 hover:scale-[1.02] transition duration-700">
        <img src="/images/overlay.webp" alt="Postcard Overlay" className="pointer-events-none select-none" />

        <video 
          ref={videoRef}
          muted
          playsInline
          autoPlay
          loop
          preload="auto"
          src="/videos/postcard-vd.mp4"
          className="pointer-events-none"
        />

        <Link 
          to="/register"
          className="post-card-btn relative z-30 cursor-pointer pointer-events-auto"
        >
          JOIN THE HEIST
        </Link>
      </div>
    </section>
  );
};

export default PostCard;
