import React, { useState } from 'react';
import Navbar from '../../components/Navbar/Navbar';
import Footer from '../../components/Footer/Footer';
import './ContactUsNow.scss';


function ContactUsNow() {
    const [formData, setFormData] = useState({
        enquiryType: 'fraud-scams',
        fullName: '',
        email: '',
        phone: '',
        country: '',
        scamWebsite: '',
        lostMoney: '',
        message: '',
    });
    


    const [isSubmitting, setIsSubmitting] = useState(false);


    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({ ...formData, [name]: value });
    };


    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
      
        try {
          const response = await fetch('http://localhost:3001/api/contact', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
          });
      
          if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Error submitting enquiry.');
          }
      
          const data = await response.json();
          alert(data.message || 'Enquiry sent successfully!');
          setFormData({
            enquiryType: 'fraud-scams',
            fullName: '',
            email: '',
            phone: '',
            country: '',
            scamWebsite: '',
            lostMoney: '',
            message: '',
          });
        } catch (error) {
          console.error('❌ Error submitting enquiry:', error);
          alert(error.message || 'There was an error submitting your enquiry.');
        } finally {
          setIsSubmitting(false);
        }
      };
      


    return (
        <div>
            <Navbar />
            <div className="contact-us-now">
                <header className="contact-header">
                    <img src="/images/logo.png" alt="Company Logo" className="company-logo" />
                </header>
                <h4>Write an Enquiry</h4>
                <form className="enquiry-form" onSubmit={handleSubmit}>
                    <label htmlFor="enquiry-type">My enquiry relates to:</label>
                    <select
                        id="enquiry-type"
                        name="enquiryType"
                        value={formData.enquiry_type}
                        onChange={handleChange}
                    >
                        <option value="fraud-scams">Fraud/Scams</option>
                        <option value="social-media">Social Media Cases</option>
                        <option value="other-cases">All other cases</option>
                    </select>


                    <label htmlFor="full-name">Full Name:</label>
                    <input
                        type="text"
                        id="full-name"
                        name="fullName"
                        value={formData.full_name}
                        onChange={handleChange}
                        placeholder="Full Name"
                        required
                    />


                    <label htmlFor="email">Your Email Address:</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        placeholder="example@email.com"
                        required
                    />


                    <label htmlFor="phone">Your Phone Number:</label>
                    <input
                        type="tel"
                        id="phone"
                        name="phone"
                        value={formData.phone}
                        onChange={handleChange}
                        placeholder="+12 345 678 901"
                        required
                    />


                    <label htmlFor="country">Your Country:</label>
                    <input
                        type="text"
                        id="country"
                        name="country"
                        value={formData.country}
                        onChange={handleChange}
                        placeholder="Country"
                        required
                    />


                    <label htmlFor="scam-website">Is there a scam website or company?</label>
                    <input
                        type="url"
                        id="scam-website"
                        name="scamWebsite"
                        value={formData.scam_website}
                        onChange={handleChange}
                        placeholder="www.scam.com"
                    />


                    <label htmlFor="lost-money">Did you lose any money?</label>
                    <input
                        type="text"
                        id="lost-money"
                        name="lostMoney"
                        value={formData.lost_money}
                        onChange={handleChange}
                        placeholder="Amount"
                    />


                    <label htmlFor="message">Please explain what happened:</label>
                    <textarea
                        id="message"
                        name="message"
                        value={formData.message}
                        onChange={handleChange}
                        rows="4"
                        placeholder="Please explain what happened"
                        required
                    />


                    <button type="submit" disabled={isSubmitting}>
                        {isSubmitting ? 'Sending...' : 'Send Enquiry Now'}
                    </button>
                </form>
            </div>
            <Footer />
        </div>
    );
}


export default ContactUsNow;




