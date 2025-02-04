import React, { useEffect, useState } from 'react';
import axios from 'axios';
import './AdminDashboard.scss';

const AdminDashboard = () => {
  const [users, setUsers] = useState([]);
  const [reports, setReports] = useState([]);
  const [investments, setInvestments] = useState([]);
  const [enquiries, setEnquiries] = useState([]);
  const [editedUsers, setEditedUsers] = useState({});

  // Function to fetch all data
  const fetchAllData = async () => {
    try {
      const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');
      if (!storedToken) {
        console.error("🚨 No token found! Login again.");
        return;
      }

      console.log("🔍 Sending Token:", storedToken);

      const headers = { Authorization: `Bearer ${storedToken}` };

      const [usersRes, reportsRes, investmentsRes, enquiriesRes] = await Promise.all([
        axios.get('http://localhost:3001/api/users', { headers }),
        axios.get('http://localhost:3001/api/reports', { headers }),
        axios.get('http://localhost:3001/api/investments', { headers }),
        axios.get('http://localhost:3001/api/contact', { headers }),
      ]);

      setUsers(usersRes.data);
      setReports(reportsRes.data);
      setInvestments(investmentsRes.data);
      setEnquiries(enquiriesRes.data);

      // Initialize editable state
      const initialEdits = {};
      usersRes.data.forEach(user => {
        initialEdits[user.id] = { ...user };
      });
      setEditedUsers(initialEdits);

      console.log("✅ All Data Fetched Successfully!");
    } catch (error) {
      console.error('❌ Error fetching data:', error.response?.data || error.message);
    }
  };

  // Auto-fetch data on mount and every 60 seconds
  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 60000); // 60 seconds
    return () => clearInterval(interval); // Cleanup on unmount
  }, []);

  // Handle changes in the editable fields
  const handleEditChange = (userId, field, value) => {
    setEditedUsers(prev => ({
      ...prev,
      [userId]: {
        ...prev[userId],
        [field]: value
      }
    }));
  };

  // Update user balance in the backend
  const updateUserBalance = async (userId) => {
    try {
      const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token');
      if (!storedToken) {
        console.error("🚨 No token found! Login again.");
        return;
      }

      const headers = { Authorization: `Bearer ${storedToken}` };
      const userData = editedUsers[userId];

      await axios.put(`localhost:3001/api/users/${userId}`, userData, { headers });

      console.log(`✅ User ${userId} updated successfully`);
      alert('User balance updated successfully!');

      fetchAllData(); // Refresh data after update
    } catch (error) {
      console.error('❌ Error updating user:', error.response?.data || error.message);
    }
  };

  return (
    <div className="admin-dashboard">
      <h1>Admin Dashboard</h1>

      {/* Users Table */}
      <h2>Users</h2>
      <table>
        <thead>
          <tr>
            <th>Id</th><th>Name</th><th>Email</th><th>Role</th>
            <th>BTC</th><th>ETH</th><th>ADA</th><th>XRP</th><th>DOGE</th><th>BNB</th><th>SOL</th><th>DOT</th><th>Total</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {users.length > 0 ? users.map((user) => (
            <tr key={user.id}>
              <td>{user.id}</td><td>{user.name}</td><td>{user.email}</td><td>{user.role}</td>
              {['BTC', 'ETH', 'ADA', 'XRP', 'DOGE', 'BNB', 'SOL', 'DOT', 'total'].map(field => (
                <td key={field}>
                  <input
                    type="number"
                    value={editedUsers[user.id]?.[field] || 0}
                    onChange={(e) => handleEditChange(user.id, field, parseFloat(e.target.value))}
                  />
                </td>
              ))}
              <td>
                <button onClick={() => updateUserBalance(user.id)}>Save</button>
              </td>
            </tr>
          )) : <tr><td colSpan="14" className="no-data">No users found</td></tr>}
        </tbody>
      </table>

      {/* Reports Table */}
      <h2>Reports</h2>
      <table>
        <thead>
          <tr><th>Name</th><th>Surname</th><th>Email</th><th>Description</th><th>Created At</th></tr>
        </thead>
        <tbody>
          {reports.length > 0 ? reports.map((report) => (
            <tr key={report.id}>
              <td>{report.name}</td><td>{report.surname}</td><td>{report.email}</td><td>{report.description}</td><td>{report.created_at}</td>
            </tr>
          )) : <tr><td colSpan="5" className="no-data">No reports found</td></tr>}
        </tbody>
      </table>

      {/* Investments Table */}
      <h2>Investments</h2>
      <table>
        <thead>
          <tr><th>Investor</th><th>Email</th><th>Phone Number</th><th>Amount</th><th>Details</th><th>Created at</th></tr>
        </thead>
        <tbody>
          {investments.length > 0 ? investments.map((investment) => (
            <tr key={investment.id}>
              <td>{investment.first_name} {investment.last_name}</td>
              <td>{investment.email}</td><td>{investment.phone_country_code} {investment.phone_number}</td><td>${investment.investment_amount}</td><td>{investment.details}</td><td>{investment.created_at}</td>
            </tr>
          )) : <tr><td colSpan="6" className="no-data">No investments found</td></tr>}
        </tbody>
      </table>

      {/* Contact Enquiries Table */}
      <h2>Contact Enquiries</h2>
      <table>
        <thead>
          <tr><th>Type</th><th>Full Name</th><th>Email</th><th>Message</th><th>Phone</th><th>Country</th><th>Scam Website</th><th>Lost Money</th><th>Created At</th></tr>
        </thead>
        <tbody>
          {enquiries.length > 0 ? enquiries.map((enquiry) => (
            <tr key={enquiry.id}>
              <td>{enquiry.enquiryType}</td><td>{enquiry.fullName}</td><td>{enquiry.email}</td><td>{enquiry.message}</td><td>{enquiry.phone}</td><td>{enquiry.country}</td><td>{enquiry.scamWebsite}</td><td>{enquiry.lostMoney}</td><td>{enquiry.created_at}</td>
            </tr>
          )) : <tr><td colSpan="9" className="no-data">No enquiries found</td></tr>}
        </tbody>
      </table>
    </div>
  );
};

export default AdminDashboard;
