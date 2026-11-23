import { useEffect } from 'react';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import NavBar from '../sections/NavBar';
import Hero from '../sections/Hero';
import FirstVideo from '../sections/FirstVideo';
import ActI from '../sections/ActI';
import ActII from '../sections/ActII';
import SecondVideo from '../sections/SecondVideo';
import ActIII from '../sections/ActIII';
import PostCard from '../sections/PostCard';
import Final from '../sections/Final';
import Outro from '../sections/Outro';

export default function LandingPage() {
  useEffect(() => {
    window.scrollTo(0, 0);
    const timer = setTimeout(() => {
      ScrollTrigger.refresh();
    }, 120);
    return () => clearTimeout(timer);
  }, []);

  return (
    <main>
      <NavBar />
      <Hero />
      <FirstVideo />
      <ActI />
      <ActII />
      <SecondVideo />
      <ActIII />
      <PostCard />
      <Final />
      <Outro />
    </main>
  );
}
