import React, { useEffect, useState } from "react";
import ReactApexChart from "react-apexcharts";
import "./MonthlyGrowth.scss";

const MonthlyGrowth = () => {
  // ✅ Initial simulated portfolio value (e.g., $10,000)
  const [seriesData, setSeriesData] = useState([
    { x: new Date().getTime(), y: [10000, 10100, 9950, 10050] }
  ]);

  useEffect(() => {
    const interval = setInterval(() => {
      addNewCandle();
    }, 0.5 * 60 * 60 * 1000); 

    return () => clearInterval(interval);
  }, []);

  const addNewCandle = () => {
    setSeriesData((prevData) => {
      const lastCandle = prevData[prevData.length - 1];
      const lastClose = lastCandle.y[3];

      // ✅ Simulate realistic small growth with occasional dips
      let open = lastClose;
      let close = open * (1 + (Math.random() * 0.01 - 0.005)); // ±0.5% change
      let high = Math.max(open, close) * (1 + Math.random() * 0.01); // Up to +1% high
      let low = Math.min(open, close) * (1 - Math.random() * 0.01); // Down to -1% low

      const newCandle = {
        x: new Date().getTime(),
        y: [open, high, low, close]
      };

      return [...prevData, newCandle];
    });
  };

  const options = {
    chart: {
      type: "candlestick",
      height: 600,
      background: "#171F2A",
    },
    title: {
      text: "Simulated Portfolio Growth",
      align: "left",
      style: { color: "#fff" },
    },
    xaxis: {
      type: "datetime",
      labels: { style: { colors: "#fff" } },
    },
    yaxis: {
      tooltip: { enabled: true },
      labels: { style: { colors: "#fff" } },
    },
    grid: {
      borderColor: "#ffffff",
    },
  };

  return (
    <div className="monthly-growth">
      <div className="chart-container">
        <ReactApexChart options={options} series={[{ data: seriesData }]} type="candlestick" height={400} />
      </div>
    </div>
  );
};

export default MonthlyGrowth;
