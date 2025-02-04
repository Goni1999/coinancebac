import React from 'react';
import './InvestToday.scss';

const InvestToday = () => {
  const websites = [
    { name: 'Coinbase', url: 'https://www.coinbase.com/' },
    { name: 'Binance', url: 'https://www.binance.com/' },
    { name: 'Kraken', url: 'https://www.kraken.com/' },
    { name: 'Gemini', url: 'https://www.gemini.com/' }
  ];

  return (
    <div className="invest-card">
      <h2 className="invest-card__title">Invest To Increase Value Further</h2>
      <div className="invest-card__content">
        {websites.map((site, index) => (
          <div key={index} className="invest-card__row">
            <button
              className="invest-card__button"
              onClick={() => window.open(site.url, '_blank')}
            >
              Connect
            </button>
            <span className="invest-card__website">{site.name}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default InvestToday;