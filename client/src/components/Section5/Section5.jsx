import React from 'react';
import './Section5.scss';

const cardData = [
    {
      id: 1,
      title: 'Report Online Fraud',
      subtitle: 'Take the First Step Against Scammers',
      description:
        'Easily report any suspicious activities or scams through our secure platform. By taking action, you play a crucial role in combating cybercrime. We ensure your reports are handled with confidentiality and urgency, connecting you to professionals who can investigate and take the necessary measures to stop fraud in its tracks. Together, we can create a safer online environment for everyone.',
      link: '/services',
    },
    {
      id: 2,
      title: 'Track Investigations',
      subtitle: 'Stay Updated on Your Case',
      description:
        'Track the progress of your reported fraud cases in real-time through our intuitive dashboard. You will receive regular updates, ensuring full transparency throughout the investigation process. Our dedicated team works tirelessly to analyze reports, gather evidence, and coordinate with the necessary authorities to resolve your case as efficiently as possible. Your peace of mind is our top priority.',
      link: '/services',
    },
    {
      id: 3,
      title: 'Safe Investments',
      subtitle: 'Invest with Confidence',
      description:
        'We provide carefully vetted investment opportunities to help you grow your wealth without worrying about fraud or scams. Our team rigorously evaluates every opportunity to ensure that all investments are secure, profitable, and aligned with industry standards. You can confidently invest your hard-earned money, knowing that we prioritize your financial security and success. Start investing with us and watch your portfolio thrive.',
      link: '/services',
    },
    {
      id: 4,
      title: '24/7 Support',
      subtitle: 'We’re Here Anytime You Need Us',
      description:
        'Our support team is available 24/7 to provide assistance whenever you need it. Whether you have questions about reporting fraud, tracking cases, or exploring safe investments, our experts are just a click or call away. We understand that online fraud can be stressful, and we are committed to offering quick, clear, and compassionate help to guide you through every step of the process.',
      link: '/services',
    },
    {
      id: 5,
      title: 'Verify Online Sources',
      subtitle: 'Check Before You Trust',
      description:
        'Before you engage with any online platform, business, or service, use our source verification tools to ensure legitimacy. We provide detailed background checks, user reviews, and validation reports to help you make informed decisions. By verifying online sources, you reduce the risk of falling victim to scams and fraudulent schemes. Trust, but verify—let us help you stay protected.',
      link: '/services',
    },
    {
      id: 6,
      title: 'Secure Payments',
      subtitle: 'Safe and Transparent Transactions',
      description:
        'Our platform enables secure, transparent, and reliable payment options for all your transactions. We work with trusted payment providers to ensure that your financial information remains encrypted and protected at all times. Say goodbye to worries about unauthorized access or fraudulent activity, and focus on making seamless, worry-free transactions for investments, purchases, or services.',
      link: '/services',
    },
    {
      id: 7,
      title: 'Educational Resources',
      subtitle: 'Stay Informed to Stay Safe',
      description:
        'Empower yourself with the knowledge to identify and avoid online scams. Our educational resources include in-depth articles, fraud awareness guides, and real-world examples of scams to look out for. By staying informed, you become your own first line of defense against fraud. Learn how scammers operate, what red flags to watch for, and how to protect yourself and your finances online.',
      link: '/services',
    },
    {
      id: 8,
      title: 'Legal Assistance',
      subtitle: 'Guidance from Professionals',
      description:
        'If you have been a victim of fraud, our legal experts are here to help. We connect you with trusted legal professionals who specialize in online fraud cases. Whether you need advice, representation, or support in recovering your losses, we ensure that you receive the help you deserve. Our network of experts will guide you through the legal process with care and professionalism.',
      link: '/services',
    },
    {
      id: 9,
      title: 'Fraud Alerts',
      subtitle: 'Stay Ahead of Scammers',
      description:
        'Subscribe to our fraud alert system to receive instant notifications about the latest scams, fraud schemes, and online threats. Our alerts are curated to keep you informed and one step ahead of scammers. By staying vigilant and proactive, you can better protect yourself and your loved ones from falling prey to cybercriminals. Stay safe, stay updated, and stay aware.',
      link: '/services',
    },
    {
      id: 10,
      title: 'Community Reports',
      subtitle: 'Learn from Real Experiences',
      description:
        'Join a growing community of users who share real experiences, reports, and insights about scams and fraud attempts. By learning from others, you gain valuable information to help identify and avoid fraudulent activities. Our community platform fosters a sense of solidarity, where everyone plays a role in creating a safer online space for all users. Share, learn, and protect together.',
      link: '/services',
    },
    {
      id: 11,
      title: 'Secure Document Verification',
      subtitle: 'Ensure Authenticity',
      description:
        'Our document verification tools help ensure that contracts, agreements, and other critical documents are authentic and tamper-proof. Before signing or committing to anything, let us verify the details to protect you from potential fraud. Whether you’re dealing with financial contracts or investment agreements, we provide the security and peace of mind you need.',
      link: '/services',
    },
    {
      id: 12,
      title: 'Fraud Prevention Tools',
      subtitle: 'Tools to Keep You Protected',
      description:
        'Our advanced fraud prevention tools use cutting-edge technology to detect, flag, and prevent suspicious activities before they become a problem. From anti-phishing software to fraud detection systems, we provide the tools you need to stay protected online. Protect yourself, your business, and your investments with proactive measures against online threats.',
      link: '/services',
    },
  ];
  
  

const Section5 = () => {
  return (
    <section className="section5">
      <h2 className="section5-header">Our Core Features</h2>
      <div className="section5-grid">
        {cardData.map((card) => (
          <div key={card.id} className="section5-card">
            <h3 className="card-title">{card.title}</h3>
            <h4 className="card-subtitle">{card.subtitle}</h4>
            <p className="card-description">{card.description}</p>
            <a href={card.link} className="learn-more">Learn More</a>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Section5;
