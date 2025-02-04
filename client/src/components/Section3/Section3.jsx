import React from 'react';
import './Section3.scss';

const Section3 = () => {
  const processes = [
    {
      id: 1,
      icon: '/images/star.png', // Replace with the actual icon paths
      title: 'Our Ethos',
      description: 'We uphold integrity, transparency, and a commitment to ethical practices in all our investigations.',
    },
    {
      id: 2,
      icon: '/images/software-application.png',
      title: 'IT Security',
      description: 'Our advanced IT systems ensure your data remains secure and protected from unauthorized access.',
    },
    {
      id: 3,
      icon: '/images/document.png',
      title: 'Confidentiality',
      description: 'We guarantee absolute confidentiality in handling your reports and investigations.',
    },
    {
      id: 4,
      icon: '/images/innovation.png',
      title: 'Innovation',
      description: 'We use cutting-edge technology and innovative approaches to tackle complex cyber scams.',
    },
  ];

  return (
    <div className="section3">
      <h3>Our Processes</h3>
      <div className="processes-grid">
        {processes.map((process) => (
          <div className="process-card" key={process.id}>
            <div className="process-icon">
              <img src={process.icon} alt={process.title} />
            </div>
            <h4>{process.title}</h4>
            <p>{process.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Section3;
