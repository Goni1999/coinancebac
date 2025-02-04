import React from 'react';
import { Link } from 'react-router-dom';
import './Section2.scss';

const Section2 = () => {
  const cards = [
    {
      id: 1,
      image: '/images/Examples.jpg', 
      description: 'Learn how to protect yourself from common cyber scams.',
      link: '/learn-more-1', 
    },
    {
      id: 2,
      image: '/images/5Stages.jpg',
      description: 'Discover how to investigate potential threats online.',
      link: '/learn-more-2', 
    },
    {
      id: 3,
      image: '/images/TypesOfInvestigations.jpg',
      description: 'Stay informed about the latest trends in cyber security.',
      link: '/learn-more-3', 
    },
  ];

  return (
    <div className="section2">
      <div className="cards-container">
        {cards.map((card) => (
          <div className="card" key={card.id}>
            <Link to={card.link}>
              <div className="card-image">
                <img src={card.image} alt={`Card ${card.id}`} />
              </div>
              <div className="card-description">
                <p>{card.description}</p>
              </div>
            </Link>
          </div>
        ))}
      </div>
      <div className="more-link">
        <Link to="/about" className="more-link-text">
          Click here for more &rarr;
        </Link>
      </div>
    </div>
  );
};

export default Section2;
