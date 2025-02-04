import React from "react";
import "./Transactions.scss";
import Sidebar from "../../Sidebar/Sidebar";
import HeaderDashboard from "../HeaderDashboard/HeaderDashboard";

const transactions = [
  {
    id: "#2E293E",
    currency: "Bitcoin (BTC)",
    date: "12 April 2024",
    status: "Complete",
    amount: "$4,315",
  },
  {
    id: "#8F5C12",
    currency: "Ethereum (ETH)",
    date: "21 May 2024",
    status: "Complete",
    amount: "$7,891",
  },
  {
    id: "#4A9C8E",
    currency: "Ripple (XRP)",
    date: "10 July 2024",
    status: "Complete",
    amount: "$3,127",
  },
  {
    id: "#1B2E3D",
    currency: "Cardano (ADA)",
    date: "19 October 2024",
    status: "Complete",
    amount: "$2,459",
  },
  {
    id: "#6C3A9D",
    currency: "Solana (SOL)",
    date: "25 December 2024",
    status: "Complete",
    amount: "$5,832",
  },
  // Pending Transactions
  {
    id: "#AB123F",
    currency: "Polkadot (DOT)",
    date: "5 January 2025",
    status: "Pending",
    amount: "$3,402",
  },
  {
    id: "#FF5A4B",
    currency: "Bitcoin (BTC)",
    date: "6 January 2025",
    status: "Pending",
    amount: "$6,800",
  },
  {
    id: "#A12E3F",
    currency: "Ethereum (ETH)",
    date: "7 January 2025",
    status: "Pending",
    amount: "$8,214",
  },
  {
    id: "#9C4F23",
    currency: "Binance Coin (BNB)",
    date: "10 January 2025",
    status: "Complete",
    amount: "$2,546",
},
{
    id: "#7B2D1F",
    currency: "Dogecoin (DOGE)",
    date: "11 January 2025",
    status: "Complete",
    amount: "$1,357",
},
{
    id: "#3C91B6",
    currency: "Shiba Inu (SHIB)",
    date: "13 January 2025",
    status: "Complete",
    amount: "$789",
},
{
    id: "#EC7A91",
    currency: "Litecoin (LTC)",
    date: "15 January 2025",
    status: "Pending",
    amount: "$4,983",
},
{
    id: "#D12C87",
    currency: "Chainlink (LINK)",
    date: "17 January 2025",
    status: "Pending",
    amount: "$2,645",
},
{
    id: "#7D5F92",
    currency: "Stellar (XLM)",
    date: "19 January 2025",
    status: "Pending",
    amount: "$1,947",
},
{
    id: "#1A9C4F",
    currency: "Polygon (MATIC)",
    date: "21 January 2025",
    status: "Complete",
    amount: "$3,175",
},
{
    id: "#4E9C5B",
    currency: "Avalanche (AVAX)",
    date: "23 January 2025",
    status: "Complete",
    amount: "$5,620",
},
{
    id: "#8F1D46",
    currency: "Uniswap (UNI)",
    date: "25 January 2025",
    status: "Pending",
    amount: "$4,245",
},
{
    id: "#A3E9B4",
    currency: "VeChain (VET)",
    date: "27 January 2025",
    status: "Complete",
    amount: "$2,654",
},

];

const Transactions = () => {
  return (
    <div>
      <HeaderDashboard
        logoSrc="./images/logo.png"
        bellIconSrc="/path/to/bell-icon.png"
        userName="VIP user"
      />
      <Sidebar />
      <div style={{ marginLeft: '20%', padding: '20px', backgroundColor: "#131720" }}>
    <div className="transactions">
      <h2 className="title">Transactions</h2>
      <div className="transactions-table">
        <table>
          <thead>
            <tr>
              <th>Transaction ID</th>
              <th>Type of Currency</th>
              <th>Date</th>
              <th>Status</th>
              <th>Amount</th>
            </tr>
          </thead>
          <tbody>
            {transactions.map((transaction, index) => (
              <tr key={index} className={transaction.status.toLowerCase()}>
                <td>{transaction.id}</td>
                <td>{transaction.currency}</td>
                <td>{transaction.date}</td>
                <td className="status">{transaction.status}</td>
                <td>{transaction.amount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  </div>
  );
};

export default Transactions;
