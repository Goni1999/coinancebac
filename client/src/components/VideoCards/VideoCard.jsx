import React from 'react';
import PropTypes from 'prop-types';
import './VideoCard.scss';

const VideoCard = ({ videos }) => {
  return (
    <div>
        <h2>More About us in the media</h2>
    <div className="video-card-container">
      {videos.map((video, index) => (
        <div key={index} className="video-card" style={{ width: '18rem', margin: '1rem' }}>
          <a href={video.videoUrl} target="_blank" rel="noopener noreferrer">
            <img src={video.thumbnail} className="video-card-img-top" alt={video.title} />
          </a>
          <div className="video-card-body">
            <h3 className="video-card-title">{video.title}</h3>
            <p className="video-card-text">{video.description}</p>
          </div>
        </div>
      ))}
    </div>
    </div>
  );
};

VideoCard.propTypes = {
  videos: PropTypes.arrayOf(
    PropTypes.shape({
      videoUrl: PropTypes.string.isRequired,
      title: PropTypes.string.isRequired,
      description: PropTypes.string.isRequired,
      thumbnail: PropTypes.string.isRequired,
    })
  ).isRequired,
};

export default VideoCard;
