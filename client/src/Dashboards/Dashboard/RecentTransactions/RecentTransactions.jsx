import React from "react";
import "./RecentTransactions.scss";

// Data for transactions
const transactions = [
  {
    logo: "https://cryptologos.cc/logos/bitcoin-btc-logo.png", // Bitcoin logo
    name: "Bitcoin (BTC)",
    time: "Today, 3:45 PM",
    amount: "$45,320",
  },
  {
    logo: "https://cryptologos.cc/logos/ethereum-eth-logo.png", // Ethereum logo
    name: "Ethereum (ETH)",
    time: "Today, 1:30 PM",
    amount: "$32,850",
  },
  {
    logo: "https://cryptologos.cc/logos/binance-coin-bnb-logo.png", // Binance Coin logo
    name: "Binance Coin (BNB)",
    time: "Today, 4:15 PM",
    amount: "$28,500",
  },
  {
    logo: "https://cryptologos.cc/logos/cardano-ada-logo.png", // Cardano logo
    name: "Cardano (ADA)",
    time: "Today, 2:20 PM",
    amount: "$26,120",
  },
  {
    logo: "https://cryptologos.cc/logos/solana-sol-logo.png", // Solana logo
    name: "Solana (SOL)",
    time: "Today, 5:10 PM",
    amount: "$50,000",
  },
];

const RecentTransactions = () => {
  return (
    <div className="recent-transactions">
      <h2 className="title">Recent Transactions</h2>
      <div className="transaction-list">
        {transactions.map((transaction, index) => (
          <div key={index} className="transaction-card">
            <img src={transaction.logo} alt={`${transaction.name} Logo`} className="currency-logo" />
            <div className="transaction-details">
              <h3 className="currency-name">{transaction.name}</h3>
              <p className="transaction-time">{transaction.time}</p>
            </div>
            <p className="transaction-amount">{transaction.amount}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RecentTransactions;
