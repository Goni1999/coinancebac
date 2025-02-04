import React from "react";
import ReactApexChart from "react-apexcharts";
import "./InvestmentGraph.scss";

const InvestmentGraph = ({ investedAmount, currentAmount }) => {
  // Calculate earnings and percentage growth
  const earnings = currentAmount - investedAmount;
  const growthPercentage = ((earnings / investedAmount) * 100).toFixed(2);

  // Data for the donut graph
  const series = [investedAmount, earnings]; // Invested vs. Earnings
  const options = {
    chart: {
      type: "donut",
      dropShadow: {
        enabled: true,
        top: 10,
        left: 10,
        blur: 8,
        opacity: 0.2,
      },
    },
    labels: ["Invested Amount", "Earnings"],
    colors: ["#3ebf81", "#fc774a"], // Custom colors
    dataLabels: {
      enabled: true,
      formatter: (val) => `${val.toFixed(1)}%`,
    },
    legend: {
      position: "bottom",
      markers: {
        width: 13,
        height: 13,
        radius: 13,
      },
    },
    plotOptions: {
      pie: {
        donut: {
          size: "60%", 
          labels: {
            show: true,
            name: {
              fontSize: "16px",
              fontWeight: "bold",
            },
            value: {
              fontSize: "14px",
              formatter: (val) => `$${parseFloat(val).toFixed(2)}`,
            },
            total: {
              show: true,
              label: "Total",
              formatter: () => `$${currentAmount.toFixed(2)}`,
            },
          },
        },
      },
    },
  };
  
  return (
    <div className="investment-graph">
      <div className="chart-container">
        <ReactApexChart options={options} series={series} type="donut" />
      </div>
      <h2 className="title">Investment Overview</h2>
      <div className="details">
        <p><strong>Invested Amount:</strong> ${investedAmount.toFixed(2)}</p>
        <p><strong>Current Amount:</strong> ${currentAmount.toFixed(2)}</p>
        <p>
          <strong>Growth:</strong> {growthPercentage}% 
          {earnings > 0 ? " 📈" : " 📉"}
        </p>
      </div>
    </div>
  );
};

export default InvestmentGraph;
