import React from 'react'
import Section5 from '../../components/Section5/Section5';
import Reviews from '../../components/Reviews/Reviews';
import ReportCaseModal from '../../components/ReportCaseModal/ReportCaseModal';
import './Services.scss';
import Navbar from '../../components/Navbar/Navbar';
import Footer from '../../components/Footer/Footer';

const Services = () => {
  return (
    <div className='Services'>
    <Navbar />
    <h1>Services Include the following:</h1>
    <Section5 />
    <h2>Inform us now and help will be on its way!</h2>
    <br />
    <ReportCaseModal />
    <br />
    <br />
    <br />
    <hr />
    <h2>For more information check our reviews</h2>
    <Reviews />
    <Footer />
    </div>
  )
}

export default Services;