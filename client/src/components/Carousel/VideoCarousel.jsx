import React, { useState, useEffect } from 'react';
import './VideoCarousel.scss';
import ReportCaseModal from '../ReportCaseModal/ReportCaseModal';

const VideoCarousel = () => {
  const slides = [
    { 
      header: "At CapitalTrust", 
      paragraph: "Step into the future of finance with us, your trusted partner in cryptocurrency investments. Experience a seamless and secure way to grow your wealth." 
    },
    { 
      header: "Invest Securely", 
      paragraph: "Rest easy knowing that the safety of your assets and personal data is our top priority. We employ cutting-edge security measures to protect you at every step." 
    },
    { 
      header: "Easy to Use", 
      paragraph: "Our user-friendly platform is designed to cater to both novices and seasoned investors, making cryptocurrency investments accessible to everyone." 
    },
    { 
      header: "Real-Time Insights", 
      paragraph: "Stay ahead of the curve with live updates on market trends and data, giving you the edge you need to make informed investment decisions." 
    },
    { 
      header: "Transparent Fees", 
      paragraph: "Enjoy peace of mind with our clear and straightforward pricing structure. No hidden charges, just fair and honest fees you can trust." 
    },
    { 
      header: "Join the Future", 
      paragraph: "Become part of the financial revolution and secure your place in the future of investing. CapitalTrust is here to guide you every step of the way." 
    }
  ];
  

  const [currentIndex, setCurrentIndex] = useState(0);

  // Auto-transition every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentIndex((prevIndex) => (prevIndex + 1) % slides.length);
    }, 8000);

    return () => clearInterval(interval);
  }, [slides.length]);

  const handleDotClick = (index) => {
    setCurrentIndex(index);
  };

  return (
    <div className="video-carousel">
      <video autoPlay muted loop className="video-background">
        <source src="/images/video7.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>
      <div className="carousel-content">
        <h1>{slides[currentIndex].header}</h1>
        <div className="carousel-text">
        <p>{slides[currentIndex].paragraph}</p>
        </div>
        <div className="modal">
        <ReportCaseModal />
        </div>
        <div className="carousel-dots">
          {slides.map((_, index) => (
            <span
              key={index}
              className={`dot ${currentIndex === index ? 'active' : ''}`}
              onClick={() => handleDotClick(index)}
            ></span>
          ))}
        </div>
      </div>
    </div>
  );
};

export default VideoCarousel;
