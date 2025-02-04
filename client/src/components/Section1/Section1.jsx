import React from 'react';
import './Section1.scss';
import ReportCaseModal from '../ReportCaseModal/ReportCaseModal';

const Section1 = () => {
  return (
    <div className="section1">
      <div className="section1-image">
        <img src="/images/image2.jpg" alt="Cyber Scams" />
      </div>
      <div className="section1-content">
        <h2>Protect Yourself from Cyber Scams</h2>
        <p>
          Cyber scams are on the rise, targeting individuals and businesses alike. 
          Our mission is to investigate, educate, and help victims reclaim their security.
        </p>
        <p>
          Whether you've been targeted or want to learn more about cyber safety, we're here to help.
        </p>
        
        <ReportCaseModal />
      </div>
    </div>
  );
};

export default Section1;
