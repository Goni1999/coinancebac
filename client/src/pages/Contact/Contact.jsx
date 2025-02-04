import React, { useState } from 'react';
import Navbar from '../../components/Navbar/Navbar';
import Footer from '../../components/Footer/Footer';
import './Contact.scss';

const Contact = () => {
    const [activeIndex, setActiveIndex] = useState(null);

    const toggleFAQ = (index) => {
        setActiveIndex(activeIndex === index ? null : index);
    };

    return (
    <div>
            <Navbar />
            <div className="faq-section">
            <h1>CapitalTrust - How Does It Work?</h1>
            <div>
                <p>In order to better understand how CapitalTrust works, and the systems we have in place for the recovery of your funds, you'll find below a series of frequently asked questions.</p>
            </div>
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(1)}>How long does an average case take to complete?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 1 ? 'active' : ''}`}>
                <p>Although our experienced team will look to complete your case (recover a substantial part if not all of your lost funds) as soon as possible, each case is unique. On average this process takes from 3 months to a year.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(2)}>What is the cost of pursuing a case via CapitalTrust?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 2 ? 'active' : ''}`}>
                <p>CapitalTrust provides the tools you need to pursue your case in the form of a detailed Investigation Report that includes a suggested Action Plan for you to follow. Such a report costs $3,500, with an additional $750 per transaction.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(3)}>Why don't you charge me at the end of the process only?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 3 ? 'active' : ''}`}>
                <p>Each case requires a significant amount of man-hours to investigate, process, and bring to successful completion. We charge a fixed fee to cover the costs of producing the investigation report, so it is necessary to arrange payment prior to the start of the investigation.</p>  
            </div>

            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(4)}>Where is CapitalTrust based?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 4 ? 'active' : ''}`}>
                <p>CapitalTrust is located in Calgary, Canada.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(5)}>How do I know that CapitalTrust isn't a scam?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 5 ? 'active' : ''}`}>
                <p>We believe that a question like that is best answered by the company's clients. We invite you to check out the hundreds of great reviews by our clients to verify that we are a legitimate and reputable organization. We are also registered with the Israeli justice department, as well as this our staff will happily forward you the relevant credentials.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(6)}>Why is CapitalTrust not regulated by the FCA (Financial Conduct Authority)?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 6 ? 'active' : ''}`}>
                <p>We are an authorized and regulated Canadian company, based outside of the UK, hence we comply with the relevant legal exemption that applies to us. However, we do adhere to all relevant legal parameters as we go about securing the recovery of your lost assets.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(7)}>Are you legal professionals?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 7 ? 'active' : ''}`}>
                <p>The services are provided by and/or under the supervision of licensed attorneys. We primarily collaborate with a team of experts, including legal professionals, to conduct the investigation and produce the subsequent Investigation Report.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(8)}>Will your actions lead to the taking of scammers to court?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 8 ? 'active' : ''}`}>
                <p>No, our services do not include court representation. But, our methods of recovering your lost money involve Alternative Dispute Resolution outside of court in order to speed up things. So we deal with the banks and relevant agencies that made the relevant transaction. We found this is a far more effective means of securing the recovery of the funds.</p>
            </div>
            
            <div className="align-collapse">
            <h2 onClick={() => toggleFAQ(9)}>Does it matter where I am based?</h2>
            <img src="images/arrow-down.svg" alt="arrow-down" />
            </div>
            <div className={`faq-content ${activeIndex === 9 ? 'active' : ''}`}>
                <p>It doesn't matter where you are based, our team can help you get your money back. So if you have the relevant documentation needed, we can help you regardless of your location. If you still have questions regarding any of this, feel free to reach out to us and we'll be happy to provide any information you require. You can contact us via phone or email, simply visit our Contact Us page for the relevant details.</p>
            </div>
            <br />
            <br />
            <div>
    <a href="/contactus" className='large'>If you have questions, please make sure to contact us today!</a></div>
        </div>
        <Footer />
    </div>
    );
};

export default Contact;
