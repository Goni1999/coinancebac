import React, { useState } from 'react';
import './CryptoTable.scss';

const CryptoTable = () => {
  const cryptoData = [
  {
    id: 1,
    name: 'Bitcoin',
    symbol: 'BTC',
    price: 43678,
    change: 1.52,
    marketCap: 820000000000,
    volume: 35000000000,
    isUp: true, // Indicates if the chart is upward or downward
  },
  {
    id: 2,
    name: 'Ethereum',
    symbol: 'ETH',
    price: 3214,
    change: -0.72,
    marketCap: 370000000000,
    volume: 20000000000,
    isUp: false,
  },
  {
    id: 3,
    name: 'Binance Coin',
    symbol: 'BNB',
    price: 478,
    change: 2.03,
    marketCap: 71000000000,
    volume: 2500000000,
    isUp: true,
  },
  {
      id: 4,
      name: 'Cardano',
      symbol: 'ADA',
      price: 0.379,
      change: -1.15,
      marketCap: 13400000000,
      volume: 840000000,
      isUp: false,
    },
    {
      id: 5,
      name: 'Solana',
      symbol: 'SOL',
      price: 23.12,
      change: 3.28,
      marketCap: 9000000000,
      volume: 450000000,
      isUp: true,
    },
    {
      id: 6,
      name: 'XRP',
      symbol: 'XRP',
      price: 0.678,
      change: 0.85,
      marketCap: 36000000000,
      volume: 1200000000,
      isUp: true,
    },
    {
      id: 7,
      name: 'Dogecoin',
      symbol: 'DOGE',
      price: 0.072,
      change: -0.43,
      marketCap: 9500000000,
      volume: 420000000,
      isUp: false,
    },
    {
      id: 8,
      name: 'Polkadot',
      symbol: 'DOT',
      price: 5.34,
      change: 1.79,
      marketCap: 6800000000,
      volume: 320000000,
      isUp: true,
    },
    {
      id: 9,
      name: 'Shiba Inu',
      symbol: 'SHIB',
      price: 0.00000823,
      change: -0.05,
      marketCap: 4700000000,
      volume: 150000000,
      isUp: false,
    },
    {
      id: 10,
      name: 'Litecoin',
      symbol: 'LTC',
      price: 93.21,
      change: 2.47,
      marketCap: 6800000000,
      volume: 500000000,
      isUp: true,
    },      
    {
      id: 11,
      name: 'Avalanche',
      symbol: 'AVAX',
      price: 18.45,
      change: 2.05,
      marketCap: 6000000000,
      volume: 350000000,
      isUp: true,
  },
  {
      id: 12,
      name: 'Polygon',
      symbol: 'MATIC',
      price: 0.872,
      change: -1.25,
      marketCap: 7200000000,
      volume: 600000000,
      isUp: false,
  },
  {
      id: 13,
      name: 'Uniswap',
      symbol: 'UNI',
      price: 6.48,
      change: 0.67,
      marketCap: 4800000000,
      volume: 300000000,
      isUp: true,
  },
  {
      id: 14,
      name: 'Cosmos',
      symbol: 'ATOM',
      price: 10.34,
      change: -0.92,
      marketCap: 3600000000,
      volume: 250000000,
      isUp: false,
  },
  {
      id: 15,
      name: 'Chainlink',
      symbol: 'LINK',
      price: 7.89,
      change: 1.12,
      marketCap: 4000000000,
      volume: 420000000,
      isUp: true,
  },
  {
      id: 16,
      name: 'Stellar',
      symbol: 'XLM',
      price: 0.125,
      change: -0.34,
      marketCap: 3300000000,
      volume: 150000000,
      isUp: false,
  },
  {
      id: 17,
      name: 'VeChain',
      symbol: 'VET',
      price: 0.024,
      change: 1.42,
      marketCap: 1700000000,
      volume: 80000000,
      isUp: true,
  },
  {
      id: 18,
      name: 'Aave',
      symbol: 'AAVE',
      price: 78.65,
      change: -1.78,
      marketCap: 1100000000,
      volume: 120000000,
      isUp: false,
  },
  {
      id: 19,
      name: 'Algorand',
      symbol: 'ALGO',
      price: 0.153,
      change: 0.98,
      marketCap: 2200000000,
      volume: 200000000,
      isUp: true,
  },
  {
      id: 20,
      name: 'Internet Computer',
      symbol: 'ICP',
      price: 5.89,
      change: -0.67,
      marketCap: 1500000000,
      volume: 95000000,
      isUp: false,
  },  
  ];

  const [favorites, setFavorites] = useState([]);
  const [requested, setRequested] = useState({});

  // Toggles favorite state for each cryptocurrency
  const toggleFavorite = (id) => {
    setFavorites((prev) =>
      prev.includes(id) ? prev.filter((fav) => fav !== id) : [...prev, id]
    );
  };

  // Handles request button click
  const handleRequest = (id) => {
    setRequested((prev) => ({
      ...prev,
      [id]: true,
    }));
  };

  return (
    <div className="crypto-table">
      <h2>Cryptocurrency Prices</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Name</th>
            <th>Price</th>
            <th>24%</th>
            <th>Market Cap</th>
            <th>Volume</th>
            <th>Charts</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {cryptoData.map((coin) => (
            <tr key={coin.id}>
              <td>
                <span
                  className={`star ${favorites.includes(coin.id) ? 'favorite' : ''}`}
                  onClick={() => toggleFavorite(coin.id)}
                >
                  ★
                </span>
              </td>
              <td>
                {coin.name} <span>({coin.symbol})</span>
              </td>
              <td>${coin.price.toLocaleString()}</td>
              <td className={coin.change > 0 ? 'positive' : 'negative'}>
                {coin.change > 0 ? `+${coin.change}` : coin.change}%
              </td>
              <td>${coin.marketCap.toLocaleString()}</td>
              <td>${coin.volume.toLocaleString()}</td>
              <td>
                <div className={`chart ${coin.isUp ? 'upward' : 'downward'}`}></div>
              </td>
              <td>
                <button
                  className="request-button"
                  onClick={() => handleRequest(coin.id)}
                  disabled={requested[coin.id]} // Disable the button after clicking
                >
                  {requested[coin.id] ? 'Requested' : 'Request'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default CryptoTable;
