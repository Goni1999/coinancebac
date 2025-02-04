import React, { useState } from "react";
import axios from "axios";
import "./ReportCaseModal.scss";

const ReportCaseModal = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    surname: "",
    email: "",
    description: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");

  // ✅ Toggle Modal
  const toggleModal = () => {
    setIsModalOpen(!isModalOpen);
    setSuccessMessage(""); // Reset success message when modal reopens
  };

  // ✅ Handle form input changes
  const handleInputChange = (e) => {
    const { id, value } = e.target;
    setFormData((prevData) => ({ ...prevData, [id]: value }));
  };

  // ✅ Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const response = await axios.post("http://localhost:3001/api/reports", formData);

      // ✅ Ensure response is JSON
      if (!response || response.status !== 201 || !response.data) {
        throw new Error("Invalid response from server");
      }

      setSuccessMessage("Your case has been submitted successfully!");
      setFormData({ name: "", surname: "", email: "", description: "" });

      // ✅ Auto-close modal after 2 seconds
      setTimeout(toggleModal, 2000);
    } catch (error) {
      console.error("❌ Error submitting report:", error);
      const errorMessage = error.response?.data?.error || "Failed to submit the report. Please try again.";
      alert(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <button className="report-button" onClick={toggleModal}>
        Report Your Case
      </button>

      {isModalOpen && (
        <div className="modal-overlay" onClick={toggleModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <img src="/images/logo.png" alt="Logo" className="modal-logo" />
            </div>
            <div className="modal-body">
              {successMessage ? (
                <p className="success-message">{successMessage}</p>
              ) : (
                <form onSubmit={handleSubmit}>
                  <div className="form-group">
                    <label htmlFor="name">Name</label>
                    <input type="text" id="name" placeholder="Enter your name" value={formData.name} onChange={handleInputChange} required />
                  </div>
                  <div className="form-group">
                    <label htmlFor="surname">Surname</label>
                    <input type="text" id="surname" placeholder="Enter your surname" value={formData.surname} onChange={handleInputChange} required />
                  </div>
                  <div className="form-group">
                    <label htmlFor="email">Email</label>
                    <input type="email" id="email" placeholder="Enter your email" value={formData.email} onChange={handleInputChange} required />
                  </div>
                  <div className="form-group">
                    <label htmlFor="description">Case Description + Amount Lost</label>
                    <textarea id="description" placeholder="Describe your case" value={formData.description} onChange={handleInputChange} required></textarea>
                  </div>
                  <button type="submit" className="submit-button" disabled={isSubmitting}>
                    {isSubmitting ? "Submitting..." : "Submit"}
                  </button>
                </form>
              )}
            </div>
            <button className="close-button" onClick={toggleModal}>
              Close
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export default ReportCaseModal;
