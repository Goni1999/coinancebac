import React from 'react';
import './Reviews.scss';

const reviews = [
  {
    id: 1,
    name: 'James Chen',
    comment: 'This platform is fantastic! Highly recommend it to anyone.',
    rating: 5,
  },
  {
    id: 2,
    name: 'Jane Smith',
    comment: 'Amazing user experience and great support team!',
    rating: 5,
  },
  {
    id: 3,
    name: 'Mark Johnson',
    comment: 'The features are well thought out and very useful.',
    rating: 5,
  },
  {
    id: 4,
    name: 'Michael Reeves',
    comment: 'Incredible support! They tailored strategies to my needs and safeguarded my digital presence effectively.',
    rating: 5,
  },
  {
    id: 5,
    name: 'Sophia Reynolds',
    comment: 'Professional, knowledgeable, and proactive. They not only helped me make smart investment choices but kept me safe from online threats.',
    rating: 5,
  },
  {
    id: 6,
    name: 'Emily Carter',
    comment: 'A game changer for my finances! Their thorough investigations uncovered potential risks I hadn’t considered."',
    rating: 5,
  }
];

const Reviews = () => {
  return (
    <section className="reviews">
      <h2 className="reviews-title">What Our Users Say</h2>
      <div className="reviews-container">
        {reviews.map((review) => (
          <div key={review.id} className="review-card">
            <div className="review-header">
              <h3 className="reviewer-name">{review.name}</h3>
              <div className="review-rating">
                {Array(review.rating)
                  .fill('⭐')
                  .join('')}
              </div>
            </div>
            <p className="review-comment">"{review.comment}"</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Reviews;
