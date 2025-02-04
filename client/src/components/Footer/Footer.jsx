import React from 'react';
import './Footer.scss';

const Footer = () => {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-section">
          <h4>About Us</h4>
          <p>
            We provide secure and reliable recovery of your funds and investment solutions. Join us and take control of your financial future.
          </p>
          <img src="images/dmca.jpg" alt="DMCA" />
        </div>
        <div className="footer-section">
          <h4>Quick Links</h4>
          <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/contactus">Invest</a></li>
            <li><a href="/contactus">Contact Us</a></li>
          </ul>
        </div>
        
        <div className="footer-section">
          <h4>Contact</h4>
          <p>Email: support@capitaltrust.com</p>
          <p>Phone: +1-234-567-890</p>
          <p>Address: 123 Crypto Lane, Blockchain City</p>
        </div>
      </div>
      <div className="footer-bottom">
        <p>© 2024 CapitalTrust. All rights reserved.</p>
      </div>
    </footer>
  );
};

export default Footer;
